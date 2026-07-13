//! Validate the release-time Gate-3 operator/HSM/source registry.

use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use xindex_ops::validate_topology;

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .context("usage: xindex-topology-check <owner-only-topology.json>")?;
    validate_file(Path::new(&path))?;
    let summary = validate_topology(&fs::read(&path).context("read topology registry")?)?;
    writeln!(
        std::io::stdout().lock(),
        "{}",
        serde_json::to_string_pretty(&summary)?
    )?;
    Ok(())
}

fn validate_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("inspect topology registry")?;
    if !path.is_absolute() || !metadata.file_type().is_file() {
        anyhow::bail!("topology registry must be an absolute non-symlink regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            anyhow::bail!("topology registry must be owner-only (mode 0600) and single-link");
        }
    }
    Ok(())
}
