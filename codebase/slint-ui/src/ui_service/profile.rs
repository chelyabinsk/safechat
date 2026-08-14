//! Profile discovery and platform data-directory helpers.

use anyhow::{Context, Result};
use directories::ProjectDirs;
use std::path::PathBuf;

pub fn available_profiles() -> Result<Vec<String>> {
    let root = profile_root()?;
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut profiles = std::fs::read_dir(root)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            (path.is_dir() && path.join("identity.db").is_file())
                .then(|| entry.file_name().to_string_lossy().into_owned())
        })
        .collect::<Vec<_>>();
    profiles.sort();
    Ok(profiles)
}

fn profile_root() -> Result<PathBuf> {
    Ok(ProjectDirs::from("", "SafeChat", "safechat")
        .context("cannot determine the platform data directory")?
        .data_dir()
        .to_path_buf())
}
