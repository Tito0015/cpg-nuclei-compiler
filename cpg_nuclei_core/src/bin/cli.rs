//! IPC shell — JSON scan + Nuclei YAML export.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;

use serde::Serialize;
use cpg_nuclei_core::{
    analyze_contract,
    cross_tx_dfg::build_cross_tx_dfg_from_source,
    cpg_schema::{DataFlowSlice, SliceEdge, SliceNode},
    exporters::{ExportAdapter, ExportContext, NucleiExporter},
    joern_cpg_bridge::invoke_z3_solver,
    parser::{parse_contract_functions, ParsedFunction},
    should_analyze_solidity_path,
    SinkType,
};

#[derive(Serialize)]
struct ScanHit {
    path: String,
    selector: String,
    severity: f32,
    vulnerability_class: String,
    sink_types: Vec<String>,
}

fn eprint_err(msg: &str) -> ! {
    let _ = writeln!(io::stderr(), "{msg}");
    process::exit(2);
}

fn parse_severity_threshold(raw: &str) -> f32 {
    let value: f32 = match raw.parse() {
        Ok(v) => v,
        Err(_) => eprint_err(&format!(
            "error: invalid severity-threshold '{raw}': expected a number"
        )),
    };
    if !value.is_finite() || value < 0.0 {
        eprint_err(&format!(
            "error: invalid severity-threshold '{raw}': must be a non-negative finite number"
        ));
    }
    value
}

fn sink_label(sink: &SinkType) -> &'static str {
    match sink {
        SinkType::LowLevelCall => "LowLevelCall",
        SinkType::ArithmeticDiv => "ArithmeticDiv",
        SinkType::StateUpdate => "StateUpdate",
        SinkType::Transfer => "Transfer",
        SinkType::ExternalCallback => "ExternalCallback",
        SinkType::SelfDestruct => "SelfDestruct",
        SinkType::ContractCreation => "ContractCreation",
    }
}

fn collect_sol_files(dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    let dir_str = dir.to_string_lossy();
    if !should_analyze_solidity_path(&dir_str) {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_sol_files(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("sol") {
            out.push(path);
        }
    }
    Ok(())
}

fn scan_dir(dir: &Path, threshold: f32) -> Result<Vec<ScanHit>, String> {
    let mut files = Vec::new();
    collect_sol_files(dir, &mut files).map_err(|e| format!("io error walking {dir:?}: {e}"))?;

    let mut hits = Vec::new();
    for path in files {
        let path_str = path.to_string_lossy().to_string();
        if !should_analyze_solidity_path(&path_str) {
            continue;
        }
        let source = fs::read_to_string(&path)
            .map_err(|e| format!("io error reading {}: {e}", path.display()))?;
        let result = analyze_contract(&source)
            .map_err(|e| format!("analysis error for {}: {e}", path.display()))?;
        for target in result.targets {
            if target.taint_severity < threshold {
                continue;
            }
            hits.push(ScanHit {
                path: path_str.clone(),
                selector: format!("0x{}", hex::encode(target.function_selector)),
                severity: target.taint_severity,
                vulnerability_class: target.vulnerability_class,
                sink_types: target.sink_types.iter().map(sink_label).map(str::to_string).collect(),
            });
        }
    }
    Ok(hits)
}

fn parsed_functions_to_slice(functions: &[ParsedFunction]) -> DataFlowSlice {
    let mut nodes: Vec<SliceNode> = Vec::new();
    let mut edges: Vec<SliceEdge> = Vec::new();
    let mut next_id: i64 = 0;
    let mut alloc = || {
        let id = next_id;
        next_id += 1;
        id
    };

    for func in functions {
        let method_id = alloc();
        nodes.push(SliceNode {
            id: method_id,
            label: "METHOD".into(),
            name: func.name.clone(),
            code: format!("function {}({})", func.name, func.params.len()),
            type_full_name: "void".into(),
            parent_method: func.name.clone(),
            parent_file: "target.sol".into(),
            line_number: Some(0),
            column_number: Some(0),
        });
        for (pname, _ptype) in &func.params {
            let pid = alloc();
            nodes.push(SliceNode {
                id: pid,
                label: "METHOD_PARAMETER_IN".into(),
                name: pname.clone(),
                code: pname.clone(),
                type_full_name: "".into(),
                parent_method: func.name.clone(),
                parent_file: "target.sol".into(),
                line_number: None,
                column_number: None,
            });
            edges.push(SliceEdge {
                src: pid,
                dst: method_id,
                label: "REACHING_DEF".into(),
            });
        }
    }

    DataFlowSlice { nodes, edges }
}

fn export_nuclei_for_source(source_path: &Path) -> Result<String, String> {
    let source = fs::read_to_string(source_path)
        .map_err(|e| format!("io error reading {}: {e}", source_path.display()))?;
    let scan = analyze_contract(&source)
        .map_err(|e| format!("analysis error for {}: {e}", source_path.display()))?;
    let target = scan
        .targets
        .into_iter()
        .max_by(|a, b| {
            a.taint_severity
                .partial_cmp(&b.taint_severity)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .ok_or_else(|| format!("no taint targets in {}", source_path.display()))?;

    let dfg = build_cross_tx_dfg_from_source(&source)
        .map_err(|e| format!("DFG construction failed: {e}"))?;
    let sat_path = invoke_z3_solver(&dfg, 30).map_err(|e| format!("reachability stub failed: {e}"))?;

    let contracts = parse_contract_functions(&source).map_err(|e| format!("parse error: {e}"))?;
    let functions: Vec<ParsedFunction> = contracts.into_iter().flat_map(|(_, fns)| fns).collect();
    let slice = parsed_functions_to_slice(&functions);

    let ctx = ExportContext {
        sat: &sat_path,
        slice: &slice,
        defect_class: &target.vulnerability_class,
        spec_id: None,
    };
    Ok(NucleiExporter.render(&ctx))
}

fn print_json<T: Serialize>(value: &T) {
    match serde_json::to_string(value) {
        Ok(json) => {
            println!("{json}");
            let _ = io::stdout().flush();
        }
        Err(e) => eprint_err(&format!("error: failed to serialize JSON: {e}")),
    }
}

fn usage() -> ! {
    eprint_err(
        "usage: cpg_nuclei_cli --scan <dir> --severity-threshold <f>\n\
               cpg_nuclei_cli --source <path> --export-nuclei",
    );
}

fn main() {
    let mut args = env::args().skip(1);
    let mut scan_dir_path: Option<PathBuf> = None;
    let mut severity_threshold: Option<f32> = None;
    let mut source_path: Option<PathBuf> = None;
    let mut export_nuclei = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--scan" => {
                let value = args.next().unwrap_or_else(|| {
                    eprint_err("error: --scan requires a path");
                });
                scan_dir_path = Some(PathBuf::from(value));
            }
            "--severity-threshold" => {
                let raw = args.next().unwrap_or_else(|| {
                    eprint_err("error: --severity-threshold requires a value");
                });
                severity_threshold = Some(parse_severity_threshold(&raw));
            }
            "--source" => {
                let value = args.next().unwrap_or_else(|| {
                    eprint_err("error: --source requires a path");
                });
                source_path = Some(PathBuf::from(value));
            }
            "--export-nuclei" => {
                export_nuclei = true;
            }
            other => eprint_err(&format!("error: unknown flag '{other}'")),
        }
    }

    if let Some(dir) = scan_dir_path {
        let threshold = severity_threshold.unwrap_or_else(|| {
            eprint_err("error: --scan requires --severity-threshold");
        });
        match scan_dir(&dir, threshold) {
            Ok(hits) => print_json(&hits),
            Err(msg) => eprint_err(&format!("error: {msg}")),
        }
        return;
    }

    if export_nuclei {
        let path = source_path.unwrap_or_else(|| {
            eprint_err("error: --export-nuclei requires --source");
        });
        match export_nuclei_for_source(&path) {
            Ok(yaml) => {
                print!("{yaml}");
                let _ = io::stdout().flush();
            }
            Err(msg) => eprint_err(&format!("error: {msg}")),
        }
        return;
    }

    usage();
}
