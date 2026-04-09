use glob::{Pattern, glob};
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
use walkdir::WalkDir;

pub mod errors;
use errors::AnalyzeError;

const SOURCE_DIRS: [&str; 4] = ["src", "tests", "examples", "benches"];
const ADVISORY_DB_DIRECTORY: &str = "advisory-db";
const CARGO_MANIFEST_FILE: &str = "Cargo.toml";
const MAX_ALIAS_RESOLUTION_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetInputMode {
    Exact,
    Glob,
}

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

#[derive(Debug, Default, Deserialize)]
struct CargoManifest {
    #[serde(default)]
    workspace: Option<CargoWorkspaceManifest>,
}

#[derive(Debug, Default, Deserialize)]
struct CargoWorkspaceManifest {
    #[serde(default)]
    members: Vec<String>,
}

#[derive(Clone, Debug, Default)]
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
    target_matchers: Vec<TargetMatcher>,
    alias_map: BTreeMap<String, String>,
    imported_paths: BTreeSet<String>,
    typed_bindings: BTreeMap<String, String>,
    seen: BTreeSet<(String, PathBuf, usize, usize, MatchKind, String)>,
    findings: Vec<Finding>,
}

#[derive(Clone, Debug)]
struct TargetMatcher {
    target: String,
    pattern: Pattern,
}

impl Detector {
    fn new(
        file: PathBuf,
        target_matchers: Vec<TargetMatcher>,
        alias_map: BTreeMap<String, String>,
        imported_paths: BTreeSet<String>,
    ) -> Self {
        Self {
            file,
            target_matchers,
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

    fn receiver_bound_type(&self, receiver: &Expr) -> Option<&str> {
        if let Expr::Path(expr_path) = receiver
            && expr_path.path.segments.len() == 1
            && expr_path.path.leading_colon.is_none()
            && expr_path.qself.is_none()
            && let Some(segment) = expr_path.path.segments.first()
        {
            let binding = segment.ident.to_string();
            return self.typed_bindings.get(&binding).map(String::as_str);
        }

        None
    }

    fn first_match_index(&self, path: &str) -> Option<usize> {
        self.target_matchers
            .iter()
            .position(|matcher| matcher.pattern.matches(path))
    }

    fn target_for_index(&self, index: usize) -> &str {
        self.target_matchers[index].target.as_str()
    }

    fn best_match_for_candidates(&self, candidates: &BTreeSet<String>) -> Option<usize> {
        let mut best_match_index = None;
        for candidate in candidates {
            if let Some(candidate_match_index) = self.first_match_index(candidate)
                && best_match_index.is_none_or(|current| candidate_match_index < current)
            {
                best_match_index = Some(candidate_match_index);
            }
        }
        best_match_index
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
            if let Some(match_index) = self.first_match_index(&canonical) {
                let target = self.target_for_index(match_index).to_owned();
                let (line, column) = line_column(node.func.span().start());
                let matched_call = if alias_used {
                    raw_path.clone()
                } else {
                    canonical.clone()
                };
                self.record_finding(Finding {
                    vulnerable_function: target,
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
        let mut candidate_paths = BTreeSet::new();

        if let Some(bound_type) = self.receiver_bound_type(&node.receiver) {
            candidate_paths.insert(format!("{bound_type}::{method_name}"));
        }

        for imported_path in &self.imported_paths {
            candidate_paths.insert(format!("{imported_path}::{method_name}"));
        }

        if let Some(match_index) = self.best_match_for_candidates(&candidate_paths) {
            let (line, column) = line_column(node.span().start());
            let receiver = simple_receiver_name(&node.receiver);
            self.record_finding(Finding {
                vulnerable_function: self.target_for_index(match_index).to_owned(),
                file: self.file.clone(),
                line,
                column,
                match_kind: MatchKind::HeuristicMethodCall,
                matched_call: format!("{receiver}.{method_name}()"),
            });
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
    let findings = analyze_crate_sources(
        consuming_crate_root,
        &target_functions,
        TargetInputMode::Exact,
    )?;

    Ok(AnalysisResult {
        vulnerable_used: !findings.is_empty(),
        target_functions,
        findings,
    })
}

pub fn analyze_globs_against_crate(
    globs: &[String],
    consuming_crate_root: &Path,
) -> Result<AnalysisResult, AnalyzeError> {
    if !consuming_crate_root.is_dir() {
        return Err(AnalyzeError::MissingCrateRoot {
            path: consuming_crate_root.to_path_buf(),
        });
    }

    let target_functions = normalize_glob_targets(globs)?;
    let findings = analyze_crate_sources(
        consuming_crate_root,
        &target_functions,
        TargetInputMode::Glob,
    )?;

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
    let findings = analyze_crate_sources(
        consuming_crate_root,
        &target_functions,
        TargetInputMode::Exact,
    )?;

    Ok(AnalysisResult {
        vulnerable_used: !findings.is_empty(),
        target_functions,
        findings,
    })
}

fn analyze_crate_sources(
    consuming_crate_root: &Path,
    target_functions: &[String],
    target_mode: TargetInputMode,
) -> Result<Vec<Finding>, AnalyzeError> {
    let target_matchers = build_target_matchers(target_functions, target_mode)?;
    let source_files = discover_source_files(consuming_crate_root)?;
    let public_aliases = discover_public_aliases(&source_files)?;

    let mut findings = Vec::new();

    for source_file in source_files {
        let mut file_findings =
            analyze_source_file(&source_file, &target_matchers, &public_aliases)?;
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

fn normalize_glob_targets(globs: &[String]) -> Result<Vec<String>, AnalyzeError> {
    if globs.is_empty() {
        return Err(AnalyzeError::MissingGlobPatterns);
    }

    let mut normalized = Vec::new();
    for glob_pattern in globs {
        let Some(normalized_pattern) = normalize_function_path(glob_pattern) else {
            return Err(AnalyzeError::InvalidGlobPattern {
                pattern: glob_pattern.clone(),
            });
        };
        normalized.push(normalized_pattern);
    }

    Ok(normalized)
}

fn build_target_matchers(
    targets: &[String],
    target_mode: TargetInputMode,
) -> Result<Vec<TargetMatcher>, AnalyzeError> {
    let mut matchers = Vec::new();

    for target in targets {
        let pattern_input = match target_mode {
            TargetInputMode::Exact => Pattern::escape(target),
            TargetInputMode::Glob => target.clone(),
        };

        let pattern =
            Pattern::new(&pattern_input).map_err(|source| AnalyzeError::ParseGlobPattern {
                pattern: target.clone(),
                source,
            })?;

        matchers.push(TargetMatcher {
            target: target.clone(),
            pattern,
        });
    }

    Ok(matchers)
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
    target_matchers: &[TargetMatcher],
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
        target_matchers.to_vec(),
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

    for scan_root in discover_scan_roots(consuming_crate_root)? {
        for directory in SOURCE_DIRS {
            let source_dir = scan_root.join(directory);
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
    }

    files.sort();
    files.dedup();
    Ok(files)
}

fn discover_scan_roots(consuming_crate_root: &Path) -> Result<Vec<PathBuf>, AnalyzeError> {
    let manifest_path = consuming_crate_root.join(CARGO_MANIFEST_FILE);
    let mut roots = vec![consuming_crate_root.to_path_buf()];
    if !manifest_path.is_file() {
        return Ok(roots);
    }

    let manifest_contents =
        fs::read_to_string(&manifest_path).map_err(|source| AnalyzeError::ReadManifest {
            path: manifest_path.clone(),
            source,
        })?;
    let manifest: CargoManifest =
        toml::from_str(&manifest_contents).map_err(|source| AnalyzeError::ParseManifest {
            path: manifest_path,
            source,
        })?;

    let Some(workspace) = manifest.workspace else {
        return Ok(roots);
    };

    for member in workspace.members {
        let mut member_roots = expand_workspace_member(consuming_crate_root, &member)?;
        roots.append(&mut member_roots);
    }

    roots.sort();
    roots.dedup();
    Ok(roots)
}

fn expand_workspace_member(
    workspace_root: &Path,
    member: &str,
) -> Result<Vec<PathBuf>, AnalyzeError> {
    let candidate = workspace_root.join(member);
    if !member.contains('*') && !member.contains('?') && !member.contains('[') {
        if candidate.is_dir() {
            return Ok(vec![candidate]);
        }
        return Ok(Vec::new());
    }

    let pattern = candidate.to_string_lossy().into_owned();
    let member_paths =
        glob(&pattern).map_err(|source| AnalyzeError::ParseWorkspaceMemberPattern {
            pattern: pattern.clone(),
            source,
        })?;

    let mut expanded = Vec::new();
    for member_path in member_paths {
        let member_path =
            member_path.map_err(|source| AnalyzeError::ExpandWorkspaceMemberPattern {
                pattern: pattern.clone(),
                source,
            })?;
        if member_path.is_dir() {
            expanded.push(member_path);
        }
    }

    Ok(expanded)
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
        UseTree::Glob(_) => {

            // TODO if it's a glob match then we've probably imported it, we should track glob imports and treat them as potential matches for method calls.
        }
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

    for _ in 0..MAX_ALIAS_RESOLUTION_DEPTH {
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

fn simple_receiver_name(expr: &Expr) -> String {
    match expr {
        Expr::Path(expr_path) => path_to_string(&expr_path.path).unwrap_or_else(|| "_".to_owned()),
        _ => "_".to_owned(),
    }
}

fn line_column(line_column: LineColumn) -> (usize, usize) {
    (line_column.line, line_column.column + 1)
}
