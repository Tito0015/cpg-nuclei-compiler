# CPG Compiler Bible — Code Property Graph & CPG-Nuclei IR

> **Engine:** Code Property Graph (CPG) — AST + CFG + PDG as a unified property graph.
> **Schema reference:** [`docs/joern_cpg_schema_merged.md`](docs/joern_cpg_schema_merged.md)
> **Joern setup:** [`JOERN_CLI_PROVISIONING.md`](JOERN_CLI_PROVISIONING.md)

---

## 1. Graph architecture

| Layer | Captures |
|-------|----------|
| **AST** | Syntactic structure |
| **CFG** | Control flow |
| **PDG** | Data and control dependencies |

The CPG enables single graph traversals that combine syntax, control, and data dependencies — required for taint-style vulnerability detection.

---

## 2. CPG-Nuclei universal IR

### Normalization pipeline

```
Source → Joern (C/C++/Java) OR solang parser (Solidity) → DataFlowSlice → Nuclei YAML
```

### Core contracts (`cpg_nuclei_core`)

| Type | Role |
|------|------|
| `DataFlowSlice` | Normalized slice — `METHOD`, `CALL`, `REACHING_DEF` nodes/edges |
| `CrossTxDfg` | Cross-function / cross-transaction data flow |
| `SatPath` | Reachability verdict (structural stub in OSS tree) |
| `ExportContext` | Bundle passed to `NucleiExporter` |

Canonical node labels are normalized in `joern_cpg_bridge.rs` before export.

---

## 3. Program slicing

Backward slicing from sinks to sources lives in:

- `backward_slice.rs` — critical path extraction
- `prune.rs` — sink-reachable backward BFS (drops dead code)
- `cpg_deserializer.rs` — Joern JSON → internal DFG

---

## 4. OSS reachability stub

The public tree uses a **structural stub** for `invoke_z3_solver`:

- External calls present in `CrossTxDfg` ⇒ SAT
- No external calls ⇒ UNSAT

Full SMT-based verification is not included in this release. See `ponytail:` comment in `joern_cpg_bridge.rs`.

---

## 5. Running the compiler

```powershell
cargo test -p cpg_nuclei_core
cargo run --example run_cpg_pipeline -- --target Vault.sol
cpg_nuclei_cli --source Vault.sol --export-nuclei
```

---

## 6. Related reading

- Fabian Yamaguchi — CPG foundations
- IFDS/IDE — interprocedural dataflow frameworks
- Joern documentation — upstream CPG tooling
