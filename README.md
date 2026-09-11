# CPG → Nuclei Closed Loop

Open-source **Code Property Graph (CPG) compiler** and **ProjectDiscovery Nuclei** exporter with a Docker verification harness.

```
Source (C/C++, Java, Go, Python, …) → Joern CPG → DataFlowSlice → Nuclei YAML → nuclei (Docker) → TP/TN report
```

## Capabilities & Limitations

This repository provides a high-integrity execution primitive for security researchers and AI agents. It operates deterministically rather than probabilistically.

**What this tool DOES (and excels at):**
* **Deterministic Translation:** Translates Joern Code Property Graphs (AST + CFG + PDG) directly into syntax-error-free Nuclei YAML.
* **Template Refactoring:** Acts as an engineering backend to convert flaky, destructive, or noisy community PoCs into schema-compliant, production-ready rules.
* **Closed-Loop Verification:** Provides a local `harness/docker_runner.py` to spin up targets, execute compiled templates, and guarantee True Positives (TP) locally before submitting Pull Requests.
* **Handling Async Logic:** Automatically enforces HTTP header hardening (e.g., `User-Agent`) and asynchronous execution delays (`wait_for`) based on code graph analysis.

**What this tool DOES NOT do:**
* **Text-to-Template Generation:** This tool cannot generate templates from natural language, CVE advisories, or bug bounty write-ups. It requires actual target source code (C/C++, Java, Go, Python) or a pre-compiled Joern CPG to trace data flows.
* **Autonomous Target Acquisition:** The provided Docker harness requires you to manually define the target container and supply the source code; it does not automatically hunt for vulnerable images.

## 🛠️ Primary Use Case: Refactoring Destructive Templates

While generating *new* templates from scratch requires target source code for Joern CPG analysis, **refactoring existing templates requires zero CPG setup**.

This repository serves as a deterministic unit-testing harness to take flaky, state-mutating, or destructive community templates and safely convert them into non-destructive, production-ready rules.

**Why Use This Tool for Refactoring?**
* **Zero CPG Overhead:** You do not need source code or Joern static analysis to refactor an existing `.yaml` template.
* **Deterministic Verification:** Use `harness/docker_runner.py` to test rules against local Docker targets, ensuring 0% syntax errors and verifying True Positives (TP) before opening upstream PRs.
* **Automated Hardening:** Enforce strict `User-Agent: Nuclei-Scanner` headers, state snapshotting, and `wait_for` timing primitives.

**3-Step Refactoring Workflow**
1. **Fetch Target Template:** Pick a community template from `projectdiscovery/nuclei-templates` that lacks proper cleanup or mutates application state.
2. **Execute Local Harness:** Spin up the target container and run the verification harness locally:
   ```bash
   python -m harness.docker_runner --template templates/CVE-2024-51483.yaml --target http://127.0.0.1:5000
   ```
3. **Submit Upstream:** Verify non-destructive execution and submit a verified Pull Request to ProjectDiscovery.

**Case Study Reference**

* **[PR #17007 (CVE-2024-51483)](https://github.com/projectdiscovery/nuclei-templates/pull/17007):** Refactored a destructive `changedetection.io` rule to capture setting snapshots via GET, perform a non-destructive check, and restore settings automatically post-scan.

## Research & Benchmarks

* **Empirical Analysis (CVE-2025-62593):** [CPG Compilation vs. LLM AI Generation: Empirical Analysis of CVE-2025-62593 Rule Accuracy](https://medium.com/@mhiritarek/cpg-compilation-vs-llm-ai-generation-empirical-analysis-of-cve-2025-62593-rule-accuracy-6ea0b27583da) — Benchmarking deterministic CPG static compilation against LLM-based template synthesis on asynchronous execution logic.
* **Architectural Overview:** [Why I Built an Open-Source CPG-to-Nuclei Compiler in Rust](https://medium.com/@mhiritarek/why-i-built-an-open-source-cpg-to-nuclei-compiler-in-rust-a1b2c3d4e5f6) — Detailed walkthrough of bridging Joern code graphs to ProjectDiscovery Nuclei DSL syntax.

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
