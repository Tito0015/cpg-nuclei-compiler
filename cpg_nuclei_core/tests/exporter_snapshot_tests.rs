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
