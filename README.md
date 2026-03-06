# cargo-didiuse

`cargo-didiuse` is a lightweight Rust static analyzer that checks whether a Rust crate calls known vulnerable functions.

It can read an OSV/RustSec-style report or scan the local RustSec advisory database against your crate and report likely unsafe call sites.

## What it does

- Detects potentially vulnerable function usage in source files by parsing Rust syntax (AST) with `syn`.
- Supports two input sources:
  - A vulnerability JSON report (`--vuln-json`)
  - The RustSec advisory DB (default: `$CARGO_HOME/advisory-db`, override with `--advisory-db`)
- Resolves and checks workspace members declared in `Cargo.toml`.
- Scans common Rust source directories (`src`, `tests`, `examples`, `benches`).
- Reports matches as:
  - direct path calls (for example `pkg::Type::method()`)
  - alias-resolved calls via `use`
  - heuristic method calls when a receiver type matches a known vulnerable type

Findings are reported as de-duplicated and sorted output.

> Note: this tool tries hard, but it is not perfect. It is a best-effort static detector and can have false positives or miss some call patterns.

## Install / build

From the project root:

```bash
cargo build
```

Optionally install:

```bash
cargo install --path .
```

## Usage

Run against a report file:

```bash
cargo run -- --vuln-json path/to/vuln_report.json
```

Run against the advisory DB for the current crate:

```bash
cargo run --
```

Run with explicit paths:

```bash
cargo run -- --advisory-db /path/to/advisory-db --package-path /path/to/crate
```

If you install the binary, you can also run:

```bash
cargo-didiuse --vuln-json path/to/vuln_report.json
```

## CLI options

- `-p, --package-path <PATH>`: crate/workspace root (default `.`)
- `-v, --vuln-json <PATH>`: path to an OSV/RustSec JSON report
- `--advisory-db <PATH>`: path to advisory DB directory (when not using `--vuln-json`)

## Exit codes

- `0`: no vulnerable usages found
- `1`: vulnerable usages found
- `2`: analysis error (invalid path, parse failures, missing advisory data, etc.)

When matches are found, each line is printed as:

```text
path:line:column [match-kind] matched_call -> vulnerable_function
```

## Notes

- Matches are printed to stdout with file/line/column, match type, matched symbol, and expected vulnerable target.
- Results are de-duplicated and sorted for readability.
