use proc_macro2::LineColumn;
use rustsec::{Database, Lockfile};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use syn::{
    Expr, ExprCall, ExprMethodCall, ItemUse, Pat, PatType, Type, UseTree,
    spanned::Spanned,
    visit::{self, Visit},
};
use thiserror::Error;
use walkdir::WalkDir;

const SOURCE_DIRS: [&str; 4] = ["src", "tests", "examples", "benches"];
const ADVISORY_DB_DIRECTORY: &str = "advisory-db";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisResult {
    pub vulnerable_used: bool,
    pub target_functions: Vec<String>,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    pub vulnerable_function: String,
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub match_kind: MatchKind,
    pub matched_call: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum MatchKind {
    DirectPathCall,
    AliasResolvedCall,
    HeuristicMethodCall,
}

#[derive(Debug, Error)]
pub enum AnalyzeError {
    #[error("consuming crate root does not exist: {path}")]
    MissingCrateRoot { path: PathBuf },

    #[error("failed to read report file {path}: {source}")]
    ReadReport {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse report JSON {path}: {source}")]
    ParseReport {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("failed to locate Cargo home directory: {source}")]
    LocateCargoHome {
        #[source]
        source: std::io::Error,
    },

    #[error("advisory database directory does not exist: {path}")]
    MissingAdvisoryDatabase { path: PathBuf },

    #[error("Cargo.lock does not exist: {path}")]
    MissingLockfile { path: PathBuf },

    #[error("failed to open advisory database {path}: {source}")]
    OpenAdvisoryDatabase {
        path: PathBuf,
        #[source]
        source: rustsec::Error,
    },

    #[error("failed to read Cargo.lock {path}: {source}")]
    LoadLockfile {
        path: PathBuf,
        #[source]
        source: rustsec::cargo_lock::Error,
    },

    #[error("failed to walk source directory {path}: {source}")]
    WalkSource {
        path: PathBuf,
        #[source]
        source: walkdir::Error,
    },

    #[error("failed to read Rust source file {path}: {source}")]
    ReadSource {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse Rust source file {path}: {source}")]
    ParseSource {
        path: PathBuf,
        #[source]
        source: syn::Error,
    },
}

#[derive(Debug, Deserialize)]
struct OsvReport {
    #[serde(default)]
    affected: Vec<OsvAffectedEntry>,
}

#[derive(Debug, Deserialize)]
struct OsvAffectedEntry {
    #[serde(default)]
    ecosystem_specific: Option<OsvEcosystemSpecific>,
}

#[derive(Debug, Default, Deserialize)]
struct OsvEcosystemSpecific {
    #[serde(default)]
    affects: Option<OsvAffects>,
    #[serde(default)]
    affected_functions: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct OsvAffects {
    #[serde(default)]
    functions: Vec<String>,
}

#[derive(Clone, Debug)]
struct MethodTarget {
    vulnerable_function: String,
    type_path: String,
}

#[derive(Default)]
struct UseCollector {
    alias_map: BTreeMap<String, String>,
    imported_paths: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for UseCollector {
    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        collect_use_tree(
            &mut Vec::new(),
            &node.tree,
            &mut self.alias_map,
            &mut self.imported_paths,
        );
        visit::visit_item_use(self, node);
    }
}

#[derive(Default)]
struct PublicUseCollector {
    alias_map: BTreeMap<String, String>,
}

impl<'ast> Visit<'ast> for PublicUseCollector {
    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        if !matches!(node.vis, syn::Visibility::Public(_)) {
            return;
        }

        collect_use_tree(
            &mut Vec::new(),
            &node.tree,
            &mut self.alias_map,
            &mut BTreeSet::new(),
        );
    }
}

struct Detector {
    file: PathBuf,
    vulnerable_functions: BTreeSet<String>,
    method_targets_by_name: BTreeMap<String, Vec<MethodTarget>>,
    alias_map: BTreeMap<String, String>,
    imported_paths: BTreeSet<String>,
    typed_bindings: BTreeMap<String, String>,
    seen: BTreeSet<(String, PathBuf, usize, usize, MatchKind, String)>,
    findings: Vec<Finding>,
}

impl Detector {
    fn new(
        file: PathBuf,
        vulnerable_functions: BTreeSet<String>,
        method_targets_by_name: BTreeMap<String, Vec<MethodTarget>>,
        alias_map: BTreeMap<String, String>,
        imported_paths: BTreeSet<String>,
    ) -> Self {
        Self {
            file,
            vulnerable_functions,
            method_targets_by_name,
            alias_map,
            imported_paths,
            typed_bindings: BTreeMap::new(),
            seen: BTreeSet::new(),
            findings: Vec::new(),
        }
    }

    fn record_finding(&mut self, finding: Finding) {
        let key = (
            finding.vulnerable_function.clone(),
            finding.file.clone(),
            finding.line,
            finding.column,
            finding.match_kind,
            finding.matched_call.clone(),
        );

        if self.seen.insert(key) {
            self.findings.push(finding);
        }
    }

    fn receiver_matches_typed_target(&self, receiver: &Expr, type_path: &str) -> bool {
        if let Expr::Path(expr_path) = receiver
            && expr_path.path.segments.len() == 1
            && expr_path.path.leading_colon.is_none()
            && expr_path.qself.is_none()
            && let Some(segment) = expr_path.path.segments.first()
        {
            let binding = segment.ident.to_string();
            return self
                .typed_bindings
                .get(&binding)
                .is_some_and(|bound_type| bound_type == type_path);
        }

        false
    }
}

impl<'ast> Visit<'ast> for Detector {
    fn visit_pat_type(&mut self, node: &'ast PatType) {
        if let Pat::Ident(pat_ident) = node.pat.as_ref()
            && let Some(type_path) = type_to_path_string(node.ty.as_ref())
        {
            let (canonical, _) = canonicalize_path(&type_path, &self.alias_map);
            self.typed_bindings
                .insert(pat_ident.ident.to_string(), canonical);
        }

        visit::visit_pat_type(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(expr_path) = node.func.as_ref()
            && let Some(raw_path) = path_to_string(&expr_path.path)
        {
            let (canonical, alias_used) = canonicalize_path(&raw_path, &self.alias_map);
            if self.vulnerable_functions.contains(&canonical) {
                let (line, column) = line_column(node.func.span().start());
                let matched_call = if alias_used {
                    raw_path.clone()
                } else {
                    canonical.clone()
                };
                self.record_finding(Finding {
                    vulnerable_function: canonical,
                    file: self.file.clone(),
                    line,
                    column,
                    match_kind: if alias_used {
                        MatchKind::AliasResolvedCall
                    } else {
                        MatchKind::DirectPathCall
                    },
                    matched_call,
                });
            }
        }

        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method_name = node.method.to_string();
        if let Some(targets) = self.method_targets_by_name.get(&method_name).cloned() {
            for target in targets {
                let strong = self.receiver_matches_typed_target(&node.receiver, &target.type_path);
                let fallback = self.imported_paths.contains(&target.type_path);
                if strong || fallback {
                    let (line, column) = line_column(node.span().start());
                    let receiver = simple_receiver_name(&node.receiver);
                    self.record_finding(Finding {
                        vulnerable_function: target.vulnerable_function,
                        file: self.file.clone(),
                        line,
                        column,
                        match_kind: MatchKind::HeuristicMethodCall,
                        matched_call: format!("{receiver}.{method_name}()"),
                    });
                }
            }
        }

        visit::visit_expr_method_call(self, node);
    }
}

pub fn analyze_report_against_crate(
    report_path: &Path,
    consuming_crate_root: &Path,
) -> Result<AnalysisResult, AnalyzeError> {
    if !consuming_crate_root.is_dir() {
        return Err(AnalyzeError::MissingCrateRoot {
            path: consuming_crate_root.to_path_buf(),
        });
    }

    let report_contents =
        fs::read_to_string(report_path).map_err(|source| AnalyzeError::ReadReport {
            path: report_path.to_path_buf(),
            source,
        })?;
    let report: OsvReport =
        serde_json::from_str(&report_contents).map_err(|source| AnalyzeError::ParseReport {
            path: report_path.to_path_buf(),
            source,
        })?;

    let target_functions = extract_target_functions(&report);
    let findings = analyze_crate_sources(consuming_crate_root, &target_functions)?;

    Ok(AnalysisResult {
        vulnerable_used: !findings.is_empty(),
        target_functions,
        findings,
    })
}

pub fn analyze_advisory_db_against_crate(
    advisory_db_path: Option<&Path>,
    consuming_crate_root: &Path,
) -> Result<AnalysisResult, AnalyzeError> {
    if !consuming_crate_root.is_dir() {
        return Err(AnalyzeError::MissingCrateRoot {
            path: consuming_crate_root.to_path_buf(),
        });
    }

    let advisory_db_path = advisory_db_path
        .map(Path::to_path_buf)
        .map(Ok)
        .unwrap_or_else(default_advisory_db_path)?;
    let lockfile_path = consuming_crate_root.join("Cargo.lock");

    let target_functions =
        extract_target_functions_from_advisory_db(&advisory_db_path, &lockfile_path)?;
    let findings = analyze_crate_sources(consuming_crate_root, &target_functions)?;

    Ok(AnalysisResult {
        vulnerable_used: !findings.is_empty(),
        target_functions,
        findings,
    })
}

fn analyze_crate_sources(
    consuming_crate_root: &Path,
    target_functions: &[String],
) -> Result<Vec<Finding>, AnalyzeError> {
    let vulnerable_functions: BTreeSet<String> = target_functions.iter().cloned().collect();
    let method_targets_by_name = build_method_targets(&vulnerable_functions);
    let source_files = discover_source_files(consuming_crate_root)?;
    let public_aliases = discover_public_aliases(&source_files)?;

    let mut findings = Vec::new();

    for source_file in source_files {
        let mut file_findings = analyze_source_file(
            &source_file,
            &vulnerable_functions,
            &method_targets_by_name,
            &public_aliases,
        )?;
        findings.append(&mut file_findings);
    }

    findings.sort_by(|a, b| {
        (
            &a.vulnerable_function,
            &a.file,
            a.line,
            a.column,
            a.match_kind,
            &a.matched_call,
        )
            .cmp(&(
                &b.vulnerable_function,
                &b.file,
                b.line,
                b.column,
                b.match_kind,
                &b.matched_call,
            ))
    });
    findings.dedup_by(|a, b| a == b);

    Ok(findings)
}

fn default_advisory_db_path() -> Result<PathBuf, AnalyzeError> {
    let cargo_home =
        home::cargo_home().map_err(|source| AnalyzeError::LocateCargoHome { source })?;
    Ok(cargo_home.join(ADVISORY_DB_DIRECTORY))
}

fn extract_target_functions_from_advisory_db(
    advisory_db_path: &Path,
    lockfile_path: &Path,
) -> Result<Vec<String>, AnalyzeError> {
    if !advisory_db_path.is_dir() {
        return Err(AnalyzeError::MissingAdvisoryDatabase {
            path: advisory_db_path.to_path_buf(),
        });
    }

    if !lockfile_path.is_file() {
        return Err(AnalyzeError::MissingLockfile {
            path: lockfile_path.to_path_buf(),
        });
    }

    let database =
        Database::open(advisory_db_path).map_err(|source| AnalyzeError::OpenAdvisoryDatabase {
            path: advisory_db_path.to_path_buf(),
            source,
        })?;
    let lockfile = Lockfile::load(lockfile_path).map_err(|source| AnalyzeError::LoadLockfile {
        path: lockfile_path.to_path_buf(),
        source,
    })?;

    let mut targets = BTreeSet::new();
    for vulnerability in database.vulnerabilities(&lockfile) {
        if let Some(functions) = vulnerability.affected_functions() {
            for function in functions {
                if let Some(normalized) = normalize_function_path(&function.to_string()) {
                    targets.insert(normalized);
                }
            }
        }
    }

    Ok(targets.into_iter().collect())
}

fn analyze_source_file(
    source_file: &Path,
    vulnerable_functions: &BTreeSet<String>,
    method_targets_by_name: &BTreeMap<String, Vec<MethodTarget>>,
    public_aliases: &BTreeMap<String, String>,
) -> Result<Vec<Finding>, AnalyzeError> {
    let source =
        fs::read_to_string(source_file).map_err(|source_error| AnalyzeError::ReadSource {
            path: source_file.to_path_buf(),
            source: source_error,
        })?;
    let ast = syn::parse_file(&source).map_err(|source_error| AnalyzeError::ParseSource {
        path: source_file.to_path_buf(),
        source: source_error,
    })?;

    let mut use_collector = UseCollector::default();
    use_collector.visit_file(&ast);

    let mut merged_alias_map = use_collector.alias_map;
    merged_alias_map.extend(public_aliases.clone());

    let imported_paths = resolve_imported_paths(&use_collector.imported_paths, &merged_alias_map);

    let mut detector = Detector::new(
        source_file.to_path_buf(),
        vulnerable_functions.clone(),
        method_targets_by_name.clone(),
        merged_alias_map,
        imported_paths,
    );
    detector.visit_file(&ast);

    Ok(detector.findings)
}

fn discover_public_aliases(
    source_files: &[PathBuf],
) -> Result<BTreeMap<String, String>, AnalyzeError> {
    let mut public_aliases = BTreeMap::new();

    for source_file in source_files {
        let source =
            fs::read_to_string(source_file).map_err(|source_error| AnalyzeError::ReadSource {
                path: source_file.to_path_buf(),
                source: source_error,
            })?;
        let ast = syn::parse_file(&source).map_err(|source_error| AnalyzeError::ParseSource {
            path: source_file.to_path_buf(),
            source: source_error,
        })?;

        let mut collector = PublicUseCollector::default();
        collector.visit_file(&ast);
        public_aliases.extend(collector.alias_map);
    }

    Ok(public_aliases)
}

fn resolve_imported_paths(
    imported_paths: &BTreeSet<String>,
    alias_map: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let mut resolved = BTreeSet::new();

    for path in imported_paths {
        resolved.insert(canonicalize_path(path, alias_map).0);

        if let Some(last_segment) = path.rsplit("::").next()
            && let Some(target) = alias_map.get(last_segment)
        {
            resolved.insert(target.clone());
        }
    }

    resolved
}

fn discover_source_files(consuming_crate_root: &Path) -> Result<Vec<PathBuf>, AnalyzeError> {
    let mut files = Vec::new();

    for directory in SOURCE_DIRS {
        let source_dir = consuming_crate_root.join(directory);
        if !source_dir.is_dir() {
            continue;
        }

        for entry in WalkDir::new(&source_dir) {
            let entry = entry.map_err(|source| AnalyzeError::WalkSource {
                path: source_dir.clone(),
                source,
            })?;

            if entry.file_type().is_file()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "rs")
            {
                files.push(entry.into_path());
            }
        }
    }

    files.sort();
    Ok(files)
}

fn extract_target_functions(report: &OsvReport) -> Vec<String> {
    let mut targets = BTreeSet::new();

    for entry in &report.affected {
        let Some(ecosystem_specific) = &entry.ecosystem_specific else {
            continue;
        };

        let primary_functions = ecosystem_specific
            .affects
            .as_ref()
            .map(|affects| affects.functions.as_slice())
            .unwrap_or(&[]);

        if !primary_functions.is_empty() {
            for function in primary_functions {
                if let Some(normalized) = normalize_function_path(function) {
                    targets.insert(normalized);
                }
            }
            continue;
        }

        for function in &ecosystem_specific.affected_functions {
            if let Some(normalized) = normalize_function_path(function) {
                targets.insert(normalized);
            }
        }
    }

    targets.into_iter().collect()
}

fn build_method_targets(
    vulnerable_functions: &BTreeSet<String>,
) -> BTreeMap<String, Vec<MethodTarget>> {
    let mut method_targets_by_name = BTreeMap::<String, Vec<MethodTarget>>::new();

    for vulnerable_function in vulnerable_functions {
        let segments: Vec<&str> = vulnerable_function.split("::").collect();
        if segments.len() < 3 {
            continue;
        }

        let type_segment = segments[segments.len() - 2];
        if !looks_like_type_segment(type_segment) {
            continue;
        }

        let method_name = segments[segments.len() - 1].to_owned();
        let type_path = segments[..segments.len() - 1].join("::");

        method_targets_by_name
            .entry(method_name)
            .or_default()
            .push(MethodTarget {
                vulnerable_function: vulnerable_function.clone(),
                type_path,
            });
    }

    for targets in method_targets_by_name.values_mut() {
        targets.sort_by(|left, right| left.vulnerable_function.cmp(&right.vulnerable_function));
    }

    method_targets_by_name
}

fn collect_use_tree(
    prefix: &mut Vec<String>,
    tree: &UseTree,
    alias_map: &mut BTreeMap<String, String>,
    imported_paths: &mut BTreeSet<String>,
) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_tree(prefix, path.tree.as_ref(), alias_map, imported_paths);
            let removed = prefix.pop();
            removed.expect("prefix stack pop should match a previous push");
        }
        UseTree::Name(name) => {
            let mut full_path = prefix.clone();
            full_path.push(name.ident.to_string());
            let full_path_string = full_path.join("::");
            alias_map.insert(name.ident.to_string(), full_path_string.clone());
            imported_paths.insert(full_path_string);
        }
        UseTree::Rename(rename) => {
            let mut full_path = prefix.clone();
            full_path.push(rename.ident.to_string());
            let full_path_string = full_path.join("::");
            alias_map.insert(rename.rename.to_string(), full_path_string.clone());
            imported_paths.insert(full_path_string);
        }
        UseTree::Group(group) => {
            for nested_tree in &group.items {
                collect_use_tree(prefix, nested_tree, alias_map, imported_paths);
            }
        }
        UseTree::Glob(_) => {}
    }
}

fn path_to_string(path: &syn::Path) -> Option<String> {
    if path.segments.is_empty() {
        return None;
    }

    Some(
        path.segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<String>>()
            .join("::"),
    )
}

fn type_to_path_string(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(type_path) if type_path.qself.is_none() => path_to_string(&type_path.path),
        _ => None,
    }
}

fn canonicalize_path(path: &str, alias_map: &BTreeMap<String, String>) -> (String, bool) {
    let mut normalized = normalize_function_path(path).unwrap_or_default();
    let mut alias_used = false;

    for _ in 0..8 {
        let Some(first_segment) = normalized.split("::").next() else {
            break;
        };
        let Some(resolved_prefix) = alias_map.get(first_segment) else {
            break;
        };

        let mut resolved = resolved_prefix.clone();
        if let Some((_, remainder)) = normalized.split_once("::")
            && !remainder.is_empty()
        {
            resolved.push_str("::");
            resolved.push_str(remainder);
        }

        if resolved == normalized {
            break;
        }

        normalized = resolved;
        alias_used = true;
    }

    (normalized, alias_used)
}

fn normalize_function_path(path: &str) -> Option<String> {
    let trimmed = path.trim().trim_start_matches("::");
    if trimmed.is_empty() {
        return None;
    }

    Some(trimmed.to_owned())
}

fn looks_like_type_segment(segment: &str) -> bool {
    segment
        .chars()
        .next()
        .is_some_and(|first| first == '<' || first.is_uppercase())
}

fn simple_receiver_name(expr: &Expr) -> String {
    match expr {
        Expr::Path(expr_path) => path_to_string(&expr_path.path).unwrap_or_else(|| "_".to_owned()),
        _ => "_".to_owned(),
    }
}

fn line_column(line_column: LineColumn) -> (usize, usize) {
    (line_column.line, line_column.column + 1)
}
