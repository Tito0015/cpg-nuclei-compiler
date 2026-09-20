//! Nuclei YAML exporter snapshot tests.

use std::collections::HashMap;

use cpg_nuclei_core::cpg_schema::{DataFlowSlice, SliceEdge, SliceNode};
use cpg_nuclei_core::exporters::{
    dispatch, ExportAdapter, ExportContext, ExportFormat, NucleiExporter,
};
use cpg_nuclei_core::joern_cpg_bridge::SatPath;

fn fixture_dataflow_slice() -> DataFlowSlice {
    DataFlowSlice {
        nodes: vec![
            SliceNode {
                id: 0,
                label: "METHOD".into(),
                name: "withdraw".into(),
                code: "function withdraw(uint256 _amount)".into(),
                type_full_name: "void".into(),
                parent_method: "Vault".into(),
                parent_file: "Vault.sol".into(),
                line_number: Some(42),
                column_number: Some(4),
            },
            SliceNode {
                id: 1,
                label: "METHOD_PARAMETER_IN".into(),
                name: "_amount".into(),
                code: "_amount".into(),
                type_full_name: "uint256".into(),
                parent_method: "withdraw".into(),
                parent_file: "Vault.sol".into(),
                line_number: Some(42),
                column_number: Some(28),
            },
            SliceNode {
                id: 2,
                label: "IDENTIFIER".into(),
                name: "recipient".into(),
                code: "recipient".into(),
                type_full_name: "address".into(),
                parent_method: "withdraw".into(),
                parent_file: "Vault.sol".into(),
                line_number: Some(43),
                column_number: Some(8),
            },
            SliceNode {
                id: 3,
                label: "CALL".into(),
                name: "call".into(),
                code: "recipient.call{value: _amount}()".into(),
                type_full_name: "".into(),
                parent_method: "withdraw".into(),
                parent_file: "Vault.sol".into(),
                line_number: Some(43),
                column_number: Some(8),
            },
        ],
        edges: vec![
            SliceEdge {
                src: 1,
                dst: 2,
                label: "REACHING_DEF".into(),
            },
            SliceEdge {
                src: 2,
                dst: 3,
                label: "ARGUMENT".into(),
            },
        ],
    }
}

fn fixture_sat_path(sat: bool) -> SatPath {
    SatPath {
        sat,
        model: HashMap::from([
            ("_amount".into(), "0x400".into()),
            ("recipient".into(), "0xDEAD".into()),
        ]),
        reason: if sat {
            "user-controlled input reaches external call without reentrancy guard".into()
        } else {
            "invariant blocks all user input from reaching call".into()
        },
        invariant_count: if sat { 2 } else { 5 },
        chain_name: "reentrancy-vault".into(),
    }
}

#[test]
fn nuclei_exporter_sat_output_is_valid_yaml() {
    let slice = fixture_dataflow_slice();
    let sat = fixture_sat_path(true);
    let ctx = ExportContext {
        sat: &sat,
        slice: &slice,
        defect_class: "unchecked-low-level-call",
        spec_id: None,
    };
    let out = NucleiExporter.render(&ctx);

    assert!(out.contains("id: cpg-nuclei-"), "missing UUID-style id");
    assert!(out.contains("info:"), "missing info block");
    assert!(out.contains("severity: high"));
    assert!(out.contains("name: \"CPG-Nuclei Verified: unchecked-low-level-call\""));
    assert!(out.contains("CPG-Nuclei Engine"));
    assert!(out.contains("verified: SAT"));
    assert!(out.contains("http:"));
    assert!(out.contains("recipient.call{value: _amount}()"));
}

#[test]
fn nuclei_exporter_unsat_output_has_low_severity() {
    let slice = fixture_dataflow_slice();
    let sat = fixture_sat_path(false);
    let ctx = ExportContext {
        sat: &sat,
        slice: &slice,
        defect_class: "unchecked-low-level-call",
        spec_id: None,
    };
    let out = NucleiExporter.render(&ctx);
    assert!(out.contains("severity: low"));
    assert!(out.contains("verified: UNSAT"));
}

#[test]
fn nuclei_exporter_with_spec_id_includes_spec_tag_and_metadata() {
    let slice = fixture_dataflow_slice();
    let sat = fixture_sat_path(true);
    let ctx = ExportContext {
        sat: &sat,
        slice: &slice,
        defect_class: "unchecked-low-level-call",
        spec_id: Some("CVE-2024-1234"),
    };
    let out = NucleiExporter.render(&ctx);
    assert!(out.contains("spec:CVE-2024-1234"));
    assert!(out.contains("spec_id: \"CVE-2024-1234\""));
}

#[test]
fn nuclei_exporter_cve_2025_62593_ray_template() {
    let slice = DataFlowSlice {
        nodes: vec![
            SliceNode {
                id: 0,
                label: "METHOD_PARAMETER_IN".into(),
                name: "entrypoint".into(),
                code: "entrypoint".into(),
                type_full_name: "".into(),
                parent_method: "submit_job".into(),
                parent_file: "ray_dashboard.py".into(),
                line_number: None,
                column_number: None,
            },
            SliceNode {
                id: 1,
                label: "CALL".into(),
                name: "POST".into(),
                code: "POST /api/jobs/ entrypoint=id".into(),
                type_full_name: "".into(),
                parent_method: "submit_job".into(),
                parent_file: "ray_dashboard.py".into(),
                line_number: None,
                column_number: None,
            },
        ],
        edges: vec![SliceEdge {
            src: 0,
            dst: 1,
            label: "REACHING_DEF".into(),
        }],
    };
    let sat = fixture_sat_path(true);
    let ctx = ExportContext {
        sat: &sat,
        slice: &slice,
        defect_class: "ray-job-submission-rce",
        spec_id: Some("CVE-2025-62593"),
    };
    let out = NucleiExporter.render(&ctx);

    assert!(out.contains("id: CVE-2025-62593"), "must use CVE id");
    assert_eq!(
        out.matches("User-Agent: Nuclei-Scanner").count(),
        2,
        "POST and GET must both use non-Mozilla UA"
    );
    assert!(out.contains("wait_for(3)"), "logs fetch must wait for async job output");
    assert!(out.contains("max-request: 2"), "max-request must match http blocks");
    assert!(!out.contains("# digest:"), "unsigned custom template");
    assert!(out.contains("POST /api/jobs/"), "must target Ray jobs API");
    assert!(out.contains("CPG-Nuclei Engine"));
}

#[test]
fn nuclei_exporter_mcp_tools_list_template() {
    let slice = DataFlowSlice {
        nodes: vec![SliceNode {
            id: 1,
            label: "CALL".into(),
            name: "POST".into(),
            code: "POST /mcp tools/list".into(),
            type_full_name: String::new(),
            parent_method: "tools_list".into(),
            parent_file: "mcp_server.ts".into(),
            line_number: None,
            column_number: None,
        }],
        edges: vec![],
    };
    let sat = fixture_sat_path(true);
    let ctx = ExportContext {
        sat: &sat,
        slice: &slice,
        defect_class: "mcp-unauthenticated-tools-list",
        spec_id: Some("MCP-TOOLS-LIST"),
    };
    let out = NucleiExporter.render(&ctx);

    assert!(out.contains("id: mcp-server-unauth-tools-list"));
    assert!(out.contains("severity: high"));
    assert!(out.contains(r#""jsonrpc":"2.0""#));
    assert!(out.contains("tools/list"));
    assert!(out.contains("MCP-Protocol-Version: 2026-07-28"));
    assert!(out.contains("mcp_tool_names"));
    assert!(out.contains("negative: true"));
    assert!(out.contains("POST /mcp"));
    assert!(out.contains("POST /messages"));
    assert!(!out.contains("# digest:"));
    assert!(out.contains("CPG-Nuclei Engine"));
}

#[test]
fn dispatch_nuclei_matches_direct_exporter() {
    let slice = fixture_dataflow_slice();
    let sat = fixture_sat_path(true);
    let ctx = ExportContext {
        sat: &sat,
        slice: &slice,
        defect_class: "test",
        spec_id: None,
    };
    assert_eq!(
        dispatch(ExportFormat::Nuclei, &ctx),
        NucleiExporter.render(&ctx)
    );
}
