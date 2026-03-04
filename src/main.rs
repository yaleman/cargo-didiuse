use clap::Parser;
use std::{path::PathBuf, process::ExitCode};

use cargo_didiuse::{MatchKind, analyze_advisory_db_against_crate, analyze_report_against_crate};

#[derive(Debug, Parser)]
#[command(about = "Check whether vulnerable functions from advisories are used by a Rust crate")]
struct Args {
    /// Path to the consuming package (crate root directory)
    #[clap(short, long, default_value = ".")]
    package_path: PathBuf,

    /// Path to an OSV/RustSec vulnerability JSON report
    #[clap(short, long)]
    vuln_json: Option<PathBuf>,

    /// Path to advisory database directory (default: $CARGO_HOME/advisory-db)
    #[clap(long)]
    advisory_db: Option<PathBuf>,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let result = if let Some(report_path) = &args.vuln_json {
        analyze_report_against_crate(report_path, &args.package_path)
    } else {
        analyze_advisory_db_against_crate(args.advisory_db.as_deref(), &args.package_path)
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
