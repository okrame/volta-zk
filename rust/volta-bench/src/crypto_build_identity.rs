//! Conservative, versioned identity for the X4c production build surface.
//!
//! Validator/report code is deliberately outside this digest. Production
//! Rust, CUDA, Lean, build manifests and frozen specifications are included.

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const X4C_CRYPTO_BUILD_ID_SCHEME: &str = "volta-x4c-crypto-build-v1";
const IDENTITY_DOMAIN: &str = "volta-zk/x4c/crypto-build-identity/v1";
const MANIFEST_DOMAIN: &str = "volta-zk/x4c/crypto-build-manifest/v1";

const EXPLICIT_FILES: &[&str] = &[
    "docs/private-weights-pcs.md",
    "docs/quantization-spec.md",
    "docs/x4c-crypto-build-identity-design.md",
    "docs/x4c-io-lifecycle-design.md",
    "lean/lake-manifest.json",
    "lean/lakefile.toml",
    "lean/lean-toolchain",
    "rust/.cargo/config.toml",
    "rust/Cargo.lock",
    "rust/Cargo.toml",
    "rust/rustfmt.toml",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct X4cCryptoBuildIdentity {
    pub scheme: String,
    pub digest_blake3: String,
    pub manifest_blake3: String,
    pub file_count: u64,
    pub source_bytes: u64,
}

fn normalized_relative(path: &Path) -> Result<String, String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => parts.push(
                value.to_str().ok_or_else(|| "crypto identity path is not UTF-8".to_owned())?,
            ),
            _ => return Err("crypto identity path is not normalized".to_owned()),
        }
    }
    Ok(parts.join("/"))
}

fn has_component(path: &Path, expected: &str) -> bool {
    path.components().any(|component| component.as_os_str() == expected)
}

pub fn x4c_crypto_identity_path_included(relative: &Path) -> bool {
    let Ok(normalized) = normalized_relative(relative) else {
        return false;
    };
    if EXPLICIT_FILES.contains(&normalized.as_str()) {
        return true;
    }
    if normalized.starts_with("rust/") {
        let file_name = relative.file_name().and_then(|value| value.to_str());
        return file_name == Some("Cargo.toml")
            || file_name == Some("build.rs")
            || (has_component(relative, "src")
                && relative.extension().and_then(|value| value.to_str()) == Some("rs"));
    }
    if normalized.starts_with("cuda/") {
        return matches!(
            relative.extension().and_then(|value| value.to_str()),
            Some("cu" | "cuh" | "cpp" | "h")
        );
    }
    normalized.starts_with("lean/")
        && relative.extension().and_then(|value| value.to_str()) == Some("lean")
}

fn collect_files(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| {
            format!("read crypto identity directory {}: {error}", directory.display())
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("read crypto identity directory entry: {error}"))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "crypto identity path escaped repository root".to_owned())?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("stat crypto identity path {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            if x4c_crypto_identity_path_included(relative) {
                return Err(format!(
                    "crypto identity refuses included symlink {}",
                    relative.display()
                ));
            }
            continue;
        }
        if metadata.is_dir() {
            if relative == Path::new(".git")
                || relative == Path::new("rust/target")
                || normalized_relative(relative)?.split('/').any(|part| part == "__pycache__")
            {
                continue;
            }
            collect_files(root, &path, files)?;
        } else if metadata.is_file() && x4c_crypto_identity_path_included(relative) {
            files.push(relative.to_path_buf());
        }
    }
    Ok(())
}

pub fn x4c_crypto_build_identity(repo_root: &Path) -> Result<X4cCryptoBuildIdentity, String> {
    let canonical_root = repo_root
        .canonicalize()
        .map_err(|error| format!("canonicalize repository root: {error}"))?;
    let mut files = Vec::new();
    collect_files(&canonical_root, &canonical_root, &mut files)?;
    files.sort_by_key(|path| normalized_relative(path).unwrap_or_default());
    if files.is_empty() {
        return Err("crypto build identity selected no files".to_owned());
    }

    let mut identity = Hasher::new_derive_key(IDENTITY_DOMAIN);
    let mut manifest = Hasher::new_derive_key(MANIFEST_DOMAIN);
    identity.update(&(files.len() as u64).to_le_bytes());
    manifest.update(&(files.len() as u64).to_le_bytes());
    let mut source_bytes = 0u64;
    for relative in &files {
        let normalized = normalized_relative(relative)?;
        let path_bytes = normalized.as_bytes();
        let contents = fs::read(canonical_root.join(relative))
            .map_err(|error| format!("read crypto identity file {normalized}: {error}"))?;
        let path_len = u64::try_from(path_bytes.len())
            .map_err(|_| "crypto identity path length overflows".to_owned())?;
        let file_len = u64::try_from(contents.len())
            .map_err(|_| "crypto identity file length overflows".to_owned())?;
        source_bytes = source_bytes
            .checked_add(file_len)
            .ok_or_else(|| "crypto identity byte count overflows".to_owned())?;
        for hasher in [&mut identity, &mut manifest] {
            hasher.update(&path_len.to_le_bytes());
            hasher.update(path_bytes);
        }
        manifest.update(&file_len.to_le_bytes());
        identity.update(&file_len.to_le_bytes());
        identity.update(&contents);
    }
    Ok(X4cCryptoBuildIdentity {
        scheme: X4C_CRYPTO_BUILD_ID_SCHEME.to_owned(),
        digest_blake3: identity.finalize().to_hex().to_string(),
        manifest_blake3: manifest.finalize().to_hex().to_string(),
        file_count: files.len() as u64,
        source_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_surface_excludes_validator_and_includes_production_sources() {
        assert!(!x4c_crypto_identity_path_included(Path::new("scripts/report.py")));
        assert!(!x4c_crypto_identity_path_included(Path::new("tests/test_report.py")));
        assert!(!x4c_crypto_identity_path_included(Path::new("docs/prototype-status.md")));
        assert!(x4c_crypto_identity_path_included(Path::new("rust/volta-pcs/src/x4/x4c_v4.rs")));
        assert!(x4c_crypto_identity_path_included(Path::new("cuda/volta_cuda_backend.cu")));
        assert!(x4c_crypto_identity_path_included(Path::new("lean/VoltaZk/X4FoldingPCSV4.lean")));
        assert!(x4c_crypto_identity_path_included(Path::new("docs/x4c-io-lifecycle-design.md")));
    }

    #[test]
    fn repository_identity_is_nonempty_and_stable_within_process() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let first = x4c_crypto_build_identity(&root).unwrap();
        let second = x4c_crypto_build_identity(&root).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.scheme, X4C_CRYPTO_BUILD_ID_SCHEME);
        assert_eq!(first.digest_blake3.len(), 64);
        assert_eq!(first.manifest_blake3.len(), 64);
        assert!(first.file_count > 100);
        assert!(first.source_bytes > 1_000_000);
    }

    #[test]
    fn validator_only_content_is_excluded_but_rust_source_is_binding() {
        let root =
            std::env::temp_dir().join(format!("volta-x4c-identity-test-{}", std::process::id()));
        let rust_source = root.join("rust/example/src/lib.rs");
        let validator = root.join("scripts/report.py");
        fs::create_dir_all(rust_source.parent().unwrap()).unwrap();
        fs::create_dir_all(validator.parent().unwrap()).unwrap();
        fs::write(&rust_source, b"pub fn value() -> u64 { 1 }\n").unwrap();
        fs::write(&validator, b"VALIDATOR = 1\n").unwrap();
        let original = x4c_crypto_build_identity(&root).unwrap();

        fs::write(&validator, b"VALIDATOR = 2\n").unwrap();
        let validator_changed = x4c_crypto_build_identity(&root).unwrap();
        assert_eq!(original, validator_changed);

        fs::write(&rust_source, b"pub fn value() -> u64 { 2 }\n").unwrap();
        let crypto_changed = x4c_crypto_build_identity(&root).unwrap();
        assert_ne!(original.digest_blake3, crypto_changed.digest_blake3);
        fs::remove_dir_all(&root).unwrap();
    }
}
