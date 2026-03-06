use std::path::PathBuf;
use thiserror::Error;

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

    #[error("failed to read Cargo manifest {path}: {source}")]
    ReadManifest {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse Cargo manifest {path}: {source}")]
    ParseManifest {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("failed to parse workspace member pattern {pattern}: {source}")]
    ParseWorkspaceMemberPattern {
        pattern: String,
        #[source]
        source: glob::PatternError,
    },

    #[error("failed to expand workspace member pattern {pattern}: {source}")]
    ExpandWorkspaceMemberPattern {
        pattern: String,
        #[source]
        source: glob::GlobError,
    },
}
