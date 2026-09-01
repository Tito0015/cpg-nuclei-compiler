# Nuclei Bible — Operational Web Verification

> **Engine:** [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei) — YAML DSL for protocol and web verification.
> **DSL reference:** [`docs/nuclei_dsl_merged.md`](docs/nuclei_dsl_merged.md)

---

## 1. Non-Destructive Testing SOP

Nuclei interacts with live environments. Follow these rules before running templates against production targets.

### State capture / restore

1. **Pre-scan snapshot:** Capture target state (settings, sessions, database) before template execution.
2. **Read-only matchers:** Prefer `status`, `word`, `regex` matchers when possible.
3. **Post-scan restore:** If a template mutates state, restore from the snapshot after execution.
4. **Watch cleanup:** Terminate headless browser sessions and clear extracted variable artifacts.

**Note:** Community CVE templates such as `CVE-2024-51483` may change application settings ([discussion](https://github.com/projectdiscovery/nuclei-templates/issues/11635)). Always snapshot and restore on real targets.

### `internal: true` extractors

Masks extracted variables from standard output — useful for OpSec, log hygiene, and multi-step template chaining.

---

## 2. Closed-loop harness

This repository runs Nuclei inside Docker via `harness/docker_runner.py`:

```powershell
python -m harness.docker_runner --template templates/fixture-tp.yaml --target http://127.0.0.1:5000
```

The runner writes a JSON report under `harness/reports/` and always uses `--rm` containers.

---

## 3. Compiler integration

The Rust `NucleiExporter` (`cpg_nuclei_core/src/exporters/nuclei_exporter.rs`) emits YAML from a verified `DataFlowSlice` + `SatPath`:

| Field | Source |
|-------|--------|
| `id` | Deterministic hash of defect class |
| `info.severity` | Derived from reachability verdict |
| `metadata.verified` | SAT / UNSAT label |
| `http.matchers` | Sink code from CPG CALL node |

Export from CLI:

```powershell
cargo run --example run_cpg_pipeline -- --target Contract.sol
```

---

## 4. Template validation

Before submitting custom templates:

```bash
nuclei -validate -t path/to/template.yaml
```

Required metadata: `id`, `info.name`, `info.author`, `info.severity`, `info.tags`, `info.reference`.

---

## 5. Vendored templates

| Template | Purpose |
|----------|---------|
| `templates/CVE-2024-51483.yaml` | Upstream Changedetection.io path traversal (MIT, ProjectDiscovery) |
| `templates/fixture-tp.yaml` | Local harness true-positive smoke test |
