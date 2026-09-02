# CPG → Nuclei Closed Loop

Open-source **Code Property Graph (CPG) compiler** and **ProjectDiscovery Nuclei** exporter with a Docker verification harness.

```
Source (C/C++, Java, Go, Python, …) → Joern CPG → DataFlowSlice → Nuclei YAML → nuclei (Docker) → TP/TN report
```

## What's included

| Component | Path |
|-----------|------|
| Joern CPG bridge | `cpg_nuclei_core/src/joern_cpg_bridge.rs` |
| CPG schema / deserializer | `cpg_nuclei_core/src/cpg_schema.rs`, `cpg_deserializer.rs` |
| DFG / taint analysis | `cpg_nuclei_core/src/cross_tx_dfg.rs`, `parser.rs`, `taint.rs` |
| Nuclei YAML exporter | `cpg_nuclei_core/src/exporters/nuclei_exporter.rs` |
| Pipeline CLI | `cpg_nuclei_core/examples/run_cpg_pipeline.rs` |
| Docker closed-loop runner | `harness/docker_runner.py` |
| Architecture docs | `docs/cpg/`, `docs/nuclei/` |

### Agentic & AI Workflow Integration

`cpg-nuclei-compiler` serves as a high-integrity execution primitive for AI coding agents and autonomous security frameworks (e.g., OpenCode, Kilo Code, Cursor, Claude Code).

Rather than relying on probabilistic LLM context windows to guess template schemas or manually trace dataflows, agents invoke this CLI to achieve deterministic graph traversals (AST + CFG + PDG) with 0% syntax-error output guarantees.
## Quick start

### Prerequisites

Install [Joern](https://joern.io/) and point `JOERN_HOME` at your distribution. See [`docs/cpg/JOERN_CLI_PROVISIONING.md`](docs/cpg/JOERN_CLI_PROVISIONING.md).

Supported ingestion paths: **C/C++**, **Java**, **Go**, **Python**, and other Joern frontends.

### Usage

```powershell
# Rust compiler tests
cargo test -p cpg_nuclei_core

# Python integration (compiler + harness)
pytest tests/test_cpg_nuclei_compiler.py

# Export Nuclei YAML from source via Joern
cargo run --example run_cpg_pipeline -- --target path/to/main.c

# Closed-loop Nuclei scan (Docker required)
python -m harness.docker_runner --template templates/CVE-2024-51483.yaml --target http://127.0.0.1:5000
```

## Non-destructive Nuclei SOP

Some community templates (including `CVE-2024-51483`) **mutate application settings** during execution. Against a live Changedetection.io instance:

1. Snapshot `/settings` (GET) before scanning.
2. Run Nuclei in an isolated environment.
3. Restore settings from the snapshot after the scan.

The local fixture server on `:5000` is a **non-production stub** for harness tests only.

## License

MIT — see [`LICENSE`](LICENSE). The vendored Nuclei template under `templates/` is from [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) (MIT).
