# Joern CLI Provisioning

How `cpg_nuclei_core` discovers `joern-parse` and `joern-slice` for C/C++/Java CPG ingestion.

## Binary layout (`JOERN_HOME`)

```
$JOERN_HOME/
├── bin/
│   ├── joern-parse
│   ├── joern-parse.bat      # Windows
│   ├── joern-slice
│   └── joern-slice.bat
└── lib/
    └── *.jar
```

## Resolution order

Implemented in `JoernConfig::discover()` (`cpg_nuclei_core/src/joern_cpg_bridge.rs`):

1. `joern-parse` / `joern-slice` on `PATH` (e.g. `scoop install joern`)
2. `$JOERN_HOME/bin/joern-parse(.bat)` if the env var is set
3. `JoernError::BinaryMissing` → fall back to the Solidity solang fast-path for `.sol` targets

## Install options

### Prebuilt release (recommended)

Download a release from [joernio/joern releases](https://github.com/joernio/joern/releases), extract, then:

```powershell
$env:JOERN_HOME = "C:\tools\joern"
```

### Build from source

Requires JVM 17+ and `sbt`:

```bash
git clone https://github.com/joernio/joern.git
cd joern
sbt "joern-cli/stage"
export JOERN_HOME="$(pwd)"
```

## Smoke test

```powershell
cargo run --example run_cpg_pipeline -- --target path/to/Vault.sol
```

For C sources, provision Joern first, then point `--target` at a `.c` file.

## Schema reference

Joern slice JSON maps 1:1 to `DataFlowSlice` in `cpg_nuclei_core/src/cpg_schema.rs`. See also [`docs/joern_cpg_schema_merged.md`](docs/joern_cpg_schema_merged.md).
