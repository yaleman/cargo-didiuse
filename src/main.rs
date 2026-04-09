use clap::Parser;
use std::{path::PathBuf, process::ExitCode};

use cargo_didiuse::{
    MatchKind, analyze_advisory_db_against_crate, analyze_globs_against_crate,
    analyze_report_against_crate,
};

#[derive(Debug, Parser)]
#[command(about = "Check whether vulnerable functions from advisories are used by a Rust crate")]
struct Args {
    /// Path to the consuming package (crate root directory)
    #[clap(short, long, default_value = ".")]
    package_path: PathBuf,

    /// Vulnerable function glob pattern to match (repeat to provide multiple patterns)
    #[clap(long)]
    glob: Vec<String>,

    /// Path to an OSV/RustSec vulnerability JSON report
    #[clap(short, long)]
    vuln_json: Option<PathBuf>,

    /// Path to advisory database directory (default: $CARGO_HOME/advisory-db)
    #[clap(long)]
    advisory_db: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InputMode {
    Glob,
    VulnerabilityReport,
    AdvisoryDatabase,
}

fn select_input_mode(args: &Args) -> InputMode {
    if !args.glob.is_empty() {
        InputMode::Glob
    } else if args.vuln_json.is_some() {
        InputMode::VulnerabilityReport
    } else {
        InputMode::AdvisoryDatabase
    }
}

fn main() -> ExitCode {
    let args = Args::parse();

    let result = match select_input_mode(&args) {
        InputMode::Glob => analyze_globs_against_crate(&args.glob, &args.package_path),
        InputMode::VulnerabilityReport => {
            let report_path = args
                .vuln_json
                .as_ref()
                .expect("vuln_json should be present in report mode");
            analyze_report_against_crate(report_path, &args.package_path)
        }
        InputMode::AdvisoryDatabase => {
            analyze_advisory_db_against_crate(args.advisory_db.as_deref(), &args.package_path)
        }
    };

    match result {
        Ok(result) => {
            if result.findings.is_empty() {
                println!("No vulnerable function usages found.");
                return ExitCode::SUCCESS;
            }

            println!(
                "Found {} vulnerable function usage match(es):",
                result.findings.len()
            );
            for finding in result.findings {
                println!(
                    "{}:{}:{} [{}] {} -> {}",
                    finding.file.display(),
                    finding.line,
                    finding.column,
                    match_kind_label(finding.match_kind),
                    finding.matched_call,
                    finding.vulnerable_function
                );
            }

            ExitCode::from(1)
        }
        Err(error) => {
            eprintln!("analysis failed: {error}");
            ExitCode::from(2)
        }
    }
}

fn match_kind_label(match_kind: MatchKind) -> &'static str {
    match match_kind {
        MatchKind::DirectPathCall => "direct",
        MatchKind::AliasResolvedCall => "alias-resolved",
        MatchKind::HeuristicMethodCall => "heuristic-method",
    }
}

#[cfg(test)]
mod tests {
    use super::{Args, InputMode, select_input_mode};
    use clap::Parser;

    #[test]
    fn parses_repeatable_glob_option() {
        let args = Args::try_parse_from([
            "cargo-didiuse",
            "--glob",
            "vuln2::ExampleStruct::broken",
            "--glob",
            "vuln2::ExampleStruct::*",
        ])
        .expect("CLI parsing should accept repeated --glob options");

        assert_eq!(
            args.glob,
            vec![
                "vuln2::ExampleStruct::broken".to_owned(),
                "vuln2::ExampleStruct::*".to_owned()
            ]
        );
    }

    #[test]
    fn glob_mode_takes_precedence_over_vuln_json() {
        let args = Args::try_parse_from([
            "cargo-didiuse",
            "--glob",
            "vuln2::*",
            "--vuln-json",
            "report.json",
        ])
        .expect("CLI parsing should accept --glob together with --vuln-json");

        assert_eq!(select_input_mode(&args), InputMode::Glob);
    }

    #[test]
    fn glob_mode_takes_precedence_over_advisory_db() {
        let args =
            Args::try_parse_from(["cargo-didiuse", "--glob", "vuln2::*", "--advisory-db", "db"])
                .expect("CLI parsing should accept --glob together with --advisory-db");

        assert_eq!(select_input_mode(&args), InputMode::Glob);
    }
}
