//! ProjectDiscovery Nuclei YAML rule generator.
//!
//! Converts verified `SatPath` + `DataFlowSlice` into a Nuclei YAML template
//! containing `id`, `info`, `metadata`, and HTTP matcher fields.

use crate::cpg_schema::SliceNode;
use super::{ExportAdapter, ExportContext};

/// Nuclei YAML severity derived from Z3 verdict and invariant count.
fn severity(verdict: bool, invariant_count: usize) -> &'static str {
    if verdict {
        match invariant_count {
            0..=1 => "critical",
            2..=4 => "high",
            _ => "medium",
        }
    } else {
        "low"
    }
}

/// Extract the first CALL-label node's `code` field as the sink signature.
fn sink_code(nodes: &[SliceNode]) -> String {
    nodes
        .iter()
        .find(|n| n.label == "CALL")
        .map(|n| n.code.clone())
        .unwrap_or_default()
}

/// Extract the parent method of the first CALL node in the slice.
fn target_function(nodes: &[SliceNode]) -> String {
    nodes
        .iter()
        .find(|n| n.label == "CALL")
        .map(|n| n.parent_method.clone())
        .unwrap_or_else(|| "unknown".into())
}

/// Build a deterministic, namespaced identifier from the defect class.
fn make_id(defect_class: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    defect_class.hash(&mut h);
    let hash = h.finish();
    format!("cpg-nuclei-{:016x}", hash)
}

/// Format a slice of strings as a YAML inline list with proper indentation.
fn yaml_inline_list(items: &[String]) -> String {
    items
        .iter()
        .map(|s| format!("      - \"{s}\""))
        .collect::<Vec<_>>()
        .join("\n")
}

impl ExportAdapter for NucleiExporter {
    fn render(&self, ctx: &ExportContext) -> String {
        let verdict_str = if ctx.sat.sat { "SAT" } else { "UNSAT" };
        let sev = severity(ctx.sat.sat, ctx.sat.invariant_count);
        let sink = sink_code(&ctx.slice.nodes);
        let target_fn = target_function(&ctx.slice.nodes);
        let id = make_id(ctx.defect_class);

        let mut tags: Vec<String> = vec![
            "cpg-nuclei".into(),
            ctx.defect_class.into(),
            "verified".into(),
        ];

        let metadata_lines = if let Some(spec) = ctx.spec_id {
            tags.push(format!("spec:{spec}"));
            format!(
                "    spec_id: \"{spec}\"\n    verified: {verdict_str}\n    invariant_count: {}\n    target_function: \"{target_fn}\"\n    chain_name: \"{}\"",
                ctx.sat.invariant_count, ctx.sat.chain_name
            )
        } else {
            format!(
                "    verified: {verdict_str}\n    invariant_count: {}\n    target_function: \"{target_fn}\"\n    chain_name: \"{}\"",
                ctx.sat.invariant_count, ctx.sat.chain_name
            )
        };

        let tags_yaml = yaml_inline_list(&tags);

        format!(
            "id: {id}
info:
  name: \"CPG-Nuclei Verified: {defect_class}\"
  author:
    - \"CPG-Nuclei Engine\"
  severity: {sev}
  tags:
{tags_yaml}
  reference:
    - \"https://github.com/Tito0015/cpg-nuclei-compiler\"
metadata:
{metadata_lines}
http:
  - matchers:
      - type: word
        part: body
        words:
          - \"{sink}\"
",
            id = id,
            defect_class = ctx.defect_class,
            sev = sev,
            sink = sink,
        )
    }
}

/// Nuclei YAML rule exporter (zero-sized type implementing [`ExportAdapter`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct NucleiExporter;