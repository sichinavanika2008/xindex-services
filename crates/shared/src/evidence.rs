//! Append-only, owner-only evidence persistence for production services.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;

const MAX_RECORD_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("unsafe evidence configuration: {0}")]
    Configuration(String),
    #[error("evidence I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("evidence serialization: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("evidence identity already exists with different bytes")]
    Conflict,
    #[error("invalid evidence record: {0}")]
    InvalidRecord(String),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EvidenceVerification {
    pub directory: PathBuf,
    pub record_count: usize,
    pub total_bytes: u64,
    pub inventory_hash_keccak256: String,
}

#[derive(Debug, Clone)]
pub struct EvidenceStore {
    directory: PathBuf,
}

impl EvidenceStore {
    /// Open an existing absolute owner-only directory. Provisioning and
    /// retention remain explicit operator responsibilities.
    ///
    /// # Errors
    /// Relative/non-directory/group-readable paths are rejected.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, EvidenceError> {
        let directory = directory.as_ref();
        if !directory.is_absolute() {
            return Err(EvidenceError::Configuration(
                "directory must be absolute".to_string(),
            ));
        }
        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.file_type().is_dir() {
            return Err(EvidenceError::Configuration(
                "path is not a real directory".to_string(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(EvidenceError::Configuration(
                    "directory must not be group/world accessible".to_string(),
                ));
            }
        }
        Ok(Self {
            directory: directory.to_path_buf(),
        })
    }

    /// Serialize and sync one exact JSON record. Existing identical bytes are
    /// an idempotent success; different bytes under one identity fail.
    ///
    /// # Errors
    /// Unsafe identity, serialization/I/O failure, or conflicting content.
    pub fn persist<T: Serialize>(
        &self,
        record_id: &str,
        value: &T,
    ) -> Result<PathBuf, EvidenceError> {
        validate_record_id(record_id)?;
        let encoded = serde_json::to_vec(value)?;
        self.persist_encoded(record_id, &encoded)
    }

    /// Persist under `<prefix>-<keccak256(json)>` for append-only source polls.
    ///
    /// # Errors
    /// Unsafe prefix, serialization/I/O failure, or a hash collision.
    pub fn persist_hashed<T: Serialize>(
        &self,
        prefix: &str,
        value: &T,
    ) -> Result<PathBuf, EvidenceError> {
        validate_record_id(prefix)?;
        let encoded = serde_json::to_vec(value)?;
        let digest = alloy_primitives::keccak256(&encoded);
        let record_id = format!(
            "{prefix}-{}",
            alloy_primitives::hex::encode(digest.as_slice())
        );
        self.persist_encoded(&record_id, &encoded)
    }

    /// Verify every record in the directory is an owner-only regular JSON file
    /// committed either by a content-addressed filename or an owner-only
    /// `.keccak256` sidecar. The returned inventory hash commits the sorted
    /// filename/content-digest pairs for reconciliation against a WORM export.
    ///
    /// # Errors
    /// Unreadable/unsafe files, malformed JSON, oversized records, or any hash
    /// mismatch.
    pub fn verify_records(&self) -> Result<EvidenceVerification, EvidenceError> {
        let mut paths = std::fs::read_dir(&self.directory)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?;
        paths.sort();
        let mut total_bytes = 0u64;
        let json_paths = paths
            .iter()
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect::<Vec<_>>();
        let mut sidecars = std::collections::HashSet::new();
        let mut inventory = Vec::new();
        for path in &json_paths {
            let metadata = validate_evidence_file(path, MAX_RECORD_BYTES)?;
            let stem = path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(|| EvidenceError::InvalidRecord("non-UTF-8 filename".to_string()))?;
            let bytes = std::fs::read(path)?;
            let actual =
                alloy_primitives::hex::encode(alloy_primitives::keccak256(&bytes).as_slice());
            let sidecar = evidence_sidecar(path);
            let expected = if sidecar.exists() {
                let sidecar_metadata = validate_evidence_file(&sidecar, 256)?;
                total_bytes = total_bytes.saturating_add(sidecar_metadata.len());
                sidecars.insert(sidecar.clone());
                std::fs::read_to_string(&sidecar)?.trim().to_string()
            } else {
                let (prefix, expected) = stem.rsplit_once('-').ok_or_else(|| {
                    EvidenceError::InvalidRecord(format!(
                        "missing filename digest/sidecar: {}",
                        path.display()
                    ))
                })?;
                validate_record_id(prefix)?;
                expected.to_string()
            };
            if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(EvidenceError::InvalidRecord(format!(
                    "invalid content digest: {}",
                    path.display()
                )));
            }
            if !actual.eq_ignore_ascii_case(&expected) {
                return Err(EvidenceError::InvalidRecord(format!(
                    "content hash mismatch: {}",
                    path.display()
                )));
            }
            let _: serde_json::Value = serde_json::from_slice(&bytes)?;
            total_bytes = total_bytes.saturating_add(metadata.len());
            let file_name = path
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| EvidenceError::InvalidRecord("non-UTF-8 filename".to_string()))?;
            inventory.extend_from_slice(file_name.as_bytes());
            inventory.push(0);
            inventory.extend_from_slice(actual.as_bytes());
            inventory.push(0xff);
        }
        for path in &paths {
            if path.extension().is_none_or(|extension| extension != "json")
                && !sidecars.contains(path)
            {
                return Err(EvidenceError::InvalidRecord(format!(
                    "unexpected directory entry {}",
                    path.display()
                )));
            }
        }
        Ok(EvidenceVerification {
            directory: self.directory.clone(),
            record_count: json_paths.len(),
            total_bytes,
            inventory_hash_keccak256: alloy_primitives::hex::encode(
                alloy_primitives::keccak256(inventory).as_slice(),
            ),
        })
    }

    fn persist_encoded(&self, record_id: &str, encoded: &[u8]) -> Result<PathBuf, EvidenceError> {
        let path = self.directory.join(format!("{record_id}.json"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                if let Err(error) = write_and_sync(&mut file, encoded) {
                    let _ = std::fs::remove_file(&path);
                    return Err(error.into());
                }
                File::open(&self.directory)?.sync_all()?;
                Ok(path)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                // Never follow an attacker-planted symlink or accept a
                // group-readable/hard-linked record as an idempotent success.
                // The append-only identity is safe only when the existing
                // object satisfies the same file invariants as a newly
                // created record.
                validate_evidence_file(&path, MAX_RECORD_BYTES)?;
                if std::fs::read(&path)? == encoded {
                    Ok(path)
                } else {
                    Err(EvidenceError::Conflict)
                }
            }
            Err(error) => Err(error.into()),
        }
    }
}

fn validate_evidence_file(path: &Path, max_bytes: u64) -> Result<std::fs::Metadata, EvidenceError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(EvidenceError::InvalidRecord(format!(
            "record is not a regular file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(EvidenceError::InvalidRecord(format!(
                "record is not owner-only/single-link: {}",
                path.display()
            )));
        }
    }
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(EvidenceError::InvalidRecord(format!(
            "record size outside 1..={max_bytes}: {}",
            path.display()
        )));
    }
    Ok(metadata)
}

fn evidence_sidecar(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".keccak256");
    PathBuf::from(name)
}

fn write_and_sync(file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
    file.write_all(bytes)?;
    file.sync_all()
}

fn validate_record_id(record_id: &str) -> Result<(), EvidenceError> {
    if record_id.is_empty()
        || record_id.len() > 200
        || !record_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(EvidenceError::Configuration(
            "record id must be 1..=200 safe ASCII characters".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures")]

    use super::*;

    #[test]
    fn append_only_store_allows_exact_retry_and_rejects_conflict() {
        let directory = std::env::temp_dir().join(format!(
            "xindex-evidence-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).expect("mkdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .expect("chmod");
        }
        let store = EvidenceStore::open(&directory).expect("open");
        let first = serde_json::json!({"source": "owned", "height": 1});
        store.persist("inbound-1", &first).expect("first");
        store.persist("inbound-1", &first).expect("idempotent");
        assert!(matches!(
            store.persist(
                "inbound-1",
                &serde_json::json!({"source": "owned", "height": 2})
            ),
            Err(EvidenceError::Conflict)
        ));
        let hashed = store.persist_hashed("quote-1", &first).expect("hashed");
        assert!(hashed
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.starts_with("quote-1-")
                    && Path::new(name)
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
            }));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn hashed_record_verification_detects_tampering() {
        let directory = std::env::temp_dir().join(format!(
            "xindex-evidence-verify-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).expect("mkdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .expect("chmod");
        }
        let store = EvidenceStore::open(&directory).expect("open");
        let path = store
            .persist_hashed("observer-block-1", &serde_json::json!({"height": 1}))
            .expect("persist");
        let verification = store.verify_records().expect("verify");
        assert_eq!(verification.record_count, 1);
        std::fs::write(&path, b"{\"height\":2}").expect("tamper fixture");
        assert!(matches!(
            store.verify_records(),
            Err(EvidenceError::InvalidRecord(_))
        ));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn fixed_identity_record_with_sidecar_verifies() {
        let directory = std::env::temp_dir().join(format!(
            "xindex-evidence-sidecar-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).expect("mkdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .expect("chmod directory");
        }
        let bytes = b"{\"epoch\":1700000000}";
        let path = directory.join(format!("1700000000-{}.json", "11".repeat(32)));
        let sidecar = evidence_sidecar(&path);
        std::fs::write(&path, bytes).expect("write record");
        std::fs::write(
            &sidecar,
            format!(
                "{}\n",
                alloy_primitives::hex::encode(alloy_primitives::keccak256(bytes).as_slice())
            ),
        )
        .expect("write sidecar");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for file in [&path, &sidecar] {
                std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600))
                    .expect("chmod record");
            }
        }
        let report = EvidenceStore::open(&directory)
            .expect("open")
            .verify_records()
            .expect("verify");
        assert_eq!(report.record_count, 1);
        assert_eq!(report.inventory_hash_keccak256.len(), 64);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_directory_and_existing_record_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root = std::env::temp_dir().join(format!(
            "xindex-evidence-symlink-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_dir_all(&root);
        let directory = root.join("records");
        std::fs::create_dir_all(&directory).expect("mkdir");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("chmod root");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("chmod records");

        let directory_link = root.join("records-link");
        symlink(&directory, &directory_link).expect("symlink directory");
        assert!(matches!(
            EvidenceStore::open(&directory_link),
            Err(EvidenceError::Configuration(_))
        ));

        let target = root.join("target.json");
        std::fs::write(&target, b"{\"height\":1}").expect("write target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("chmod target");
        symlink(&target, directory.join("inbound-1.json")).expect("symlink record");
        let store = EvidenceStore::open(&directory).expect("open real directory");
        assert!(matches!(
            store.persist("inbound-1", &serde_json::json!({"height": 1})),
            Err(EvidenceError::InvalidRecord(_))
        ));

        let _ = std::fs::remove_dir_all(root);
    }
}
