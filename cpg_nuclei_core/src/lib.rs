//! CPG-Nuclei compiler — Joern bridge, DFG taint tracking, Nuclei export.

pub mod backward_slice;
pub mod cpg_deserializer;
pub mod cpg_schema;
pub mod cross_tx_dfg;
pub mod dfg;
pub mod exporters;
pub mod joern_cpg_bridge;
pub mod parser;
pub mod prune;
pub mod taint;
pub mod types;

pub use types::{
    classify_vulnerability, SinkType, StaticAnalysisResult, TaintTarget,
};

use std::path::Path;
use thiserror::Error;

const VENDORED_DIR_NAMES: &[&str] = &[
    "lib",
    "forge-std",
    "openzeppelin-contracts",
    "openzeppelin-contracts-upgradeable",
    "node_modules",
];

pub fn should_analyze_solidity_path(path: &str) -> bool {
    let p = Path::new(path);
    for component in p.components() {
        if let Some(name) = component.as_os_str().to_str() {
            if VENDORED_DIR_NAMES.contains(&name) {
                return false;
            }
        }
    }
    true
}

#[derive(Error, Debug)]
pub enum StaticAnalysisError {
    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Analysis error: {0}")]
    AnalysisError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub fn analyze_contract(source: &str) -> Result<StaticAnalysisResult, StaticAnalysisError> {
    let contracts = parser::parse_contract_functions(source)?;
    let entry_functions: Vec<&parser::ParsedFunction> = contracts
        .iter()
        .flat_map(|(_, fns)| fns.iter())
        .filter(|f| f.is_entry_point)
        .collect();
    let total_entry_count = entry_functions.len();

    let mut targets = Vec::new();

    for func in &entry_functions {
        let dfg = dfg::build_function_dfg(func);
        let taint_paths = taint::propagate_taint(&dfg);

        if !taint_paths.is_empty() {
            let selector = parser::compute_selector(&func.name, &func.params);
            let severity = taint::compute_severity(&taint_paths);
            let sink_types = taint::extract_sink_types(&taint_paths);
            let vulnerability_class = classify_vulnerability(&sink_types);

            targets.push(TaintTarget {
                function_selector: selector,
                function_name: func.name.clone(),
                taint_severity: severity,
                sink_types,
                vulnerability_class,
            });
        }
    }

    let pruned_entry_count = targets.len();

    Ok(StaticAnalysisResult {
        contract_name: parser::extract_contract_name(source).unwrap_or_default(),
        targets,
        pruned_entry_count,
        total_entry_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_analyze_first_party_paths() {
        assert!(should_analyze_solidity_path("contracts/Vault.sol"));
        assert!(should_analyze_solidity_path(""));
    }

    #[test]
    fn test_should_reject_vendored_paths() {
        assert!(!should_analyze_solidity_path(
            "lib/openzeppelin-contracts/contracts/token/ERC20.sol"
        ));
        assert!(!should_analyze_solidity_path(
            "node_modules/@openzeppelin/contracts/token/ERC20.sol"
        ));
    }
}
