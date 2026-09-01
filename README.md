# CPG → Nuclei Closed Loop

Open-source **Code Property Graph (CPG) compiler** and **ProjectDiscovery Nuclei** exporter with a Docker verification harness.

```
Source (.sol / Joern CPG) → DataFlowSlice → Nuclei YAML → nuclei (Docker) → TP/TN report
```

## What's included

| Component | Path |
|-----------|------|
| Joern CPG bridge | `cpg_nuclei_core/src/joern_cpg_bridge.rs` |
| CPG schema / deserializer | `cpg_nuclei_core/src/cpg_schema.rs`, `cpg_deserializer.rs` |
| Solidity fast-path DFG | `cpg_nuclei_core/src/cross_tx_dfg.rs`, `parser.rs`, `taint.rs` |
| Nuclei YAML exporter | `cpg_nuclei_core/src/exporters/nuclei_exporter.rs` |
| Pipeline CLI | `cpg_nuclei_core/examples/run_cpg_pipeline.rs` |
| Docker closed-loop runner | `harness/docker_runner.py` |
| Architecture docs | `docs/cpg/`, `docs/nuclei/` |

## Quick start

```powershell
# Rust compiler tests
cargo test -p cpg_nuclei_core

# Python integration (compiler + harness)
pytest tests/test_cpg_nuclei_compiler.py

# Closed-loop Nuclei scan (Docker required)
python -m harness.docker_runner --template templates/CVE-2024-51483.yaml --target http://127.0.0.1:5000
```

### Export Nuclei YAML from Solidity

```powershell
cargo run --example run_cpg_pipeline -- --target path/to/Contract.sol
```

### Optional Joern (C/C++/Java)

Set `JOERN_HOME` to a staged Joern distribution. See [`docs/cpg/JOERN_CLI_PROVISIONING.md`](docs/cpg/JOERN_CLI_PROVISIONING.md).

When Joern is missing, Solidity targets use the built-in solang fast-path.

## Non-destructive Nuclei SOP

Some community templates (including `CVE-2024-51483`) **mutate application settings** during execution. Against a live Changedetection.io instance:

1. Snapshot `/settings` (GET) before scanning.
2. Run Nuclei in an isolated environment.
3. Restore settings from the snapshot after the scan.

The local fixture server on `:5000` is a **non-production stub** for harness tests only.

## Reachability stub (OSS)

This tree ships a **structural reachability stub** instead of a full SMT solver: external calls in the DFG ⇒ SAT, otherwise UNSAT. Formal Z3 verification is intentionally out of scope for this public release.

## License

MIT — see [`LICENSE`](LICENSE). The vendored Nuclei template under `templates/` is from [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) (MIT).
