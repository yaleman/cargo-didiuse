# AGENTS: cargo-didiuse

## What this crate is

`cargo-didiuse` is a Rust static analysis tool that checks Rust source for calls to vulnerable functions.

- It supports a CLI (`src/main.rs`) and a reusable library API (`src/lib.rs`).
- It accepts:
  - an explicit OSV/RustSec-style vulnerability report JSON (`--vuln-json`), or
  - the local RustSec advisory database (default: `$CARGO_HOME/advisory-db`), or
  - one or more explicit vulnerable-target glob patterns (`--glob`).
- Output is a list of candidate vulnerable usages with file/line/column and match kind.

## Core design

- The CLI parses args with `clap`, selects the input source, and exits with:
  - `0` when no matches are found,
  - `1` when matches are found,
  - `2` when analysis fails.
- Input source precedence is: `--glob` first, then `--vuln-json`, then advisory DB.
- `analyze_globs_against_crate` normalizes and validates CLI glob patterns, then runs source analysis against those target patterns.
- `analyze_report_against_crate` loads report JSON, extracts target function paths, and runs source analysis.
- `analyze_advisory_db_against_crate` reads `Cargo.lock`, queries RustSec DB for vulnerable `affected_functions`, and runs source analysis.
- Source analysis is AST-driven (`syn`), scanning `src`, `tests`, `examples`, `benches` across workspace members if present.
- Call matching is done by:
  - direct path call detection (`pkg::Type::method`),
  - alias-resolved path calls via `use` imports,
  - heuristic method-call detection by combining observed receiver/import type paths with called method names and matching those against target patterns (exact or glob).
- `UseCollector` and `PublicUseCollector` build alias/import maps (including public `use` exports) to improve path resolution.
- Findings are deduplicated, sorted, and returned as structured results (`AnalysisResult` and `Finding`).
- Errors are modeled as a typed `AnalyzeError` enum with contextual path/source info.

## Key behavior and limits to preserve

- Best-effort detection: there can be false positives and false negatives due to aliasing/type inference limits.
- The code is currently tuned for simplicity and maintainability, not exhaustive Rust semantic analysis.

## Crate layout

- `src/main.rs`: CLI entry, argument handling, user-facing output.
- `src/lib.rs`: all parsing, advisory/report loading, workspace scanning, AST visitors, matching logic, and result/error types.

## Maintenance rules

- Update this `AGENTS.md` whenever the application design changes, including new workflows, analysis behavior, module boundaries, or public API/CLI contract changes.
- Keep `README.md` aligned when user-facing behavior changes or docs drift (CLI behavior, supported sources/outputs, scanning rules, exit codes, or usage examples).
