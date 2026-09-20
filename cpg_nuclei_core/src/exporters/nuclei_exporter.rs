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

const DEFAULT_ASYNC_POLL_SECS: u8 = 3;

/// Append `?{{wait_for(N)}}` to a GET path for async job-log polling.
fn wait_for_query_suffix(seconds: u8) -> String {
    format!("?{{{{wait_for({})}}}}", seconds)
}

/// Detect two-stage job-submit → log-retrieval chains from CPG slice + SAT metadata.
///
/// ponytail: alpha heuristic matches Ray URL paths (`/jobs`, `/logs`) and chain_name
/// taxonomies. Upgrade path: read an abstract `async_task` / `async_poll` tag from CPG
/// slice metadata instead of raw CALL `code` strings when Joern export supports it.
fn detect_job_log_poll_delay(ctx: &ExportContext) -> Option<u8> {
    let call_codes: Vec<&str> = ctx
        .slice
        .nodes
        .iter()
        .filter(|n| n.label == "CALL")
        .map(|n| n.code.as_str())
        .collect();

    let has_job_submit = call_codes
        .iter()
        .any(|c| c.contains("POST") && (c.contains("/jobs") || c.contains("/job")));
    let has_log_fetch = call_codes
        .iter()
        .any(|c| c.contains("GET") && c.contains("/logs"));

    if has_job_submit && has_log_fetch {
        return Some(DEFAULT_ASYNC_POLL_SECS);
    }
    if has_job_submit
        && (ctx.sat.chain_name.contains("api-jobs")
            || ctx.sat.chain_name.ends_with("-jobs")
            || ctx.defect_class.contains("job-submission"))
    {
        return Some(DEFAULT_ASYNC_POLL_SECS);
    }
    None
}

/// Full Nuclei template for Ray job-submission RCE (CVE-2025-62593).
fn render_cve_2025_62593(ctx: &ExportContext) -> String {
    let verdict_str = if ctx.sat.sat { "SAT" } else { "UNSAT" };
    let target_fn = target_function(&ctx.slice.nodes);
    let delay = detect_job_log_poll_delay(ctx).unwrap_or(DEFAULT_ASYNC_POLL_SECS);
    let poll = wait_for_query_suffix(delay);

    format!(
        r#"id: CVE-2025-62593

info:
  name: Ray - Remote Code Execution
  author:
    - CPG-Nuclei Engine
  severity: critical
  description: |
    Ray versions prior to 2.52.0 allow unauthenticated remote code execution via the job submission API at /api/jobs/. A weak User-Agent heuristic (rejecting Mozilla-prefixed headers) can be bypassed by non-browser clients, enabling arbitrary command execution when the dashboard is network-reachable.
  impact: |
    Unauthenticated attackers with network access to the Ray Dashboard can submit jobs that execute arbitrary commands on the host.
  remediation: |
    Upgrade Ray to version 2.52.0 or later and enable RAY_AUTH_MODE=token. Restrict dashboard access to trusted networks.
  reference:
    - https://github.com/ray-project/ray/security/advisories/GHSA-q279-jhrf-cc6v
    - https://github.com/projectdiscovery/nuclei-templates/issues/16961
    - https://nvd.nist.gov/vuln/detail/CVE-2025-62593
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
    cve-id: CVE-2025-62593
    cwe-id: CWE-94
  metadata:
    verified: true
    max-request: 2
    vendor: ray_project
    product: ray
    spec_id: "CVE-2025-62593"
    cpg_verified: {verdict_str}
    invariant_count: {invariant_count}
    target_function: "{target_fn}"
    chain_name: "{chain_name}"
    shodan-query:
      - http.favicon.hash:463802404
      - http.html:"ray dashboard"
    fofa-query:
      - icon_hash=463802404
      - body="ray dashboard"
  tags: cve,cve2025,rce,ray,kev,vuln

variables:
  jobid: "Job_{{{{rand_base(6)}}}}"

http:
  - raw:
      - |
        POST /api/jobs/ HTTP/1.1
        Host: {{{{Hostname}}}}
        User-Agent: Nuclei-Scanner
        Content-Type: application/json

        {{"entrypoint":"id","submission_id":"{{{{jobid}}}}"}}

      - |
        GET /api/jobs/{{{{jobid}}}}/logs{poll} HTTP/1.1
        Host: {{{{Hostname}}}}
        User-Agent: Nuclei-Scanner

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: regex
        part: body
        regex:
          - 'uid=\d+'
"#,
        verdict_str = verdict_str,
        invariant_count = ctx.sat.invariant_count,
        target_fn = target_fn,
        chain_name = ctx.sat.chain_name,
        poll = poll,
    )
}

const MCP_TOOLS_LIST_PATHS: &[&str] = &["/mcp", "/messages", "/sse", "/"];

const MCP_TOOLS_LIST_RPC_BODY: &str =
    r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;

/// Nuclei template for unauthenticated MCP `tools/list` exposure (nuclei-templates #16735).
fn render_mcp_tools_list_exposure(ctx: &ExportContext) -> String {
    let verdict_str = if ctx.sat.sat { "SAT" } else { "UNSAT" };
    let target_fn = target_function(&ctx.slice.nodes);

    let http_blocks = MCP_TOOLS_LIST_PATHS
        .iter()
        .map(|path| render_mcp_tools_list_http_block(path))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"id: mcp-server-unauth-tools-list

info:
  name: MCP Server - Unauthenticated tools/list Exposure
  author:
    - CPG-Nuclei Engine
  severity: high
  description: |
    Model Context Protocol (MCP) HTTP transport exposes the JSON-RPC 2.0 tools/list method without authentication, allowing anyone to enumerate tool capabilities (often including file I/O or shell-adjacent primitives).
  impact: |
    Unauthenticated tool enumeration enables targeted prompt-injection and follow-on abuse of exposed MCP tools.
  remediation: |
    Require authentication on every MCP HTTP endpoint (Bearer token, API key, or mTLS). Do not expose MCP dashboards on untrusted networks.
  reference:
    - https://github.com/projectdiscovery/nuclei-templates/issues/16735
    - https://mcpsafe.io/threats/MCP-217
    - https://modelcontextprotocol.io/specification/draft/basic/security_best_practices
  classification:
    cwe-id: CWE-306
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
    cvss-score: 7.5
  metadata:
    verified: true
    max-request: {max_request}
    spec_id: "MCP-TOOLS-LIST"
    cpg_verified: {verdict_str}
    invariant_count: {invariant_count}
    target_function: "{target_fn}"
    chain_name: "{chain_name}"
  tags: mcp,misconfig,unauth,exposure,jsonrpc

http:
{http_blocks}
"#,
        max_request = MCP_TOOLS_LIST_PATHS.len(),
        verdict_str = verdict_str,
        invariant_count = ctx.sat.invariant_count,
        target_fn = target_fn,
        chain_name = ctx.sat.chain_name,
        http_blocks = http_blocks,
    )
}

fn render_mcp_tools_list_http_block(path: &str) -> String {
    format!(
        r#"  - raw:
      - |
        POST {path} HTTP/1.1
        Host: {{{{Hostname}}}}
        MCP-Protocol-Version: 2026-07-28
        Accept: application/json, text/event-stream
        Content-Type: application/json
        User-Agent: Nuclei-Scanner

        {rpc_body}
    extractors:
      - type: regex
        name: mcp_tool_names
        part: body
        group: 1
        regex:
          - '"name"\s*:\s*"([^"]+)"'
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - '"jsonrpc"'
          - '"2.0"'
        condition: and
      - type: word
        part: body
        words:
          - '"result"'
      - type: word
        part: body
        words:
          - '"tools"'
          - '"inputSchema"'
        condition: or
      - type: word
        part: body
        words:
          - '"error"'
          - 'code":-32'
          - 'Unauthorized'
          - '401'
        negative: true
      - type: regex
        part: body
        regex:
          - '"name"\s*:\s*"[^"]+"'
"#,
        path = path,
        rpc_body = MCP_TOOLS_LIST_RPC_BODY,
    )
}

impl ExportAdapter for NucleiExporter {
    fn render(&self, ctx: &ExportContext) -> String {
        if ctx.spec_id == Some("CVE-2025-62593") {
            return render_cve_2025_62593(ctx);
        }
        if ctx.spec_id == Some("MCP-TOOLS-LIST") {
            return render_mcp_tools_list_exposure(ctx);
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpg_schema::{DataFlowSlice, SliceEdge, SliceNode};
    use crate::joern_cpg_bridge::SatPath;

    fn ray_slice_two_calls() -> DataFlowSlice {
        DataFlowSlice {
            nodes: vec![
                SliceNode {
                    id: 1,
                    label: "CALL".into(),
                    name: "POST".into(),
                    code: "POST /api/jobs/ entrypoint=id".into(),
                    type_full_name: String::new(),
                    parent_method: "submit_job".into(),
                    parent_file: String::new(),
                    line_number: None,
                    column_number: None,
                },
                SliceNode {
                    id: 2,
                    label: "CALL".into(),
                    name: "GET".into(),
                    code: "GET /api/jobs/{{jobid}}/logs".into(),
                    type_full_name: String::new(),
                    parent_method: "get_job_logs".into(),
                    parent_file: String::new(),
                    line_number: None,
                    column_number: None,
                },
            ],
            edges: vec![SliceEdge {
                src: 1,
                dst: 2,
                label: "CONTROL_FLOW".into(),
            }],
        }
    }

    #[test]
    fn wait_for_query_suffix_format() {
        assert_eq!(wait_for_query_suffix(3), "?{{wait_for(3)}}");
    }

    #[test]
    fn detect_job_log_poll_delay_two_call_nodes() {
        let slice = ray_slice_two_calls();
        let sat = SatPath {
            sat: true,
            model: std::collections::HashMap::new(),
            reason: String::new(),
            invariant_count: 0,
            chain_name: "ray-api-jobs".into(),
        };
        let ctx = ExportContext {
            sat: &sat,
            slice: &slice,
            defect_class: "ray-job-submission-rce",
            spec_id: Some("CVE-2025-62593"),
        };
        assert_eq!(detect_job_log_poll_delay(&ctx), Some(3));
    }

    #[test]
    fn detect_job_log_poll_delay_negative() {
        let slice = DataFlowSlice {
            nodes: vec![SliceNode {
                id: 0,
                label: "CALL".into(),
                name: "sink".into(),
                code: "echo hello".into(),
                type_full_name: String::new(),
                parent_method: "main".into(),
                parent_file: String::new(),
                line_number: None,
                column_number: None,
            }],
            edges: vec![],
        };
        let sat = SatPath {
            sat: true,
            model: std::collections::HashMap::new(),
            reason: String::new(),
            invariant_count: 0,
            chain_name: "generic".into(),
        };
        let ctx = ExportContext {
            sat: &sat,
            slice: &slice,
            defect_class: "generic-defect",
            spec_id: None,
        };
        assert_eq!(detect_job_log_poll_delay(&ctx), None);
    }
}
