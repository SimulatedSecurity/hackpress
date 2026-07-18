use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Load target URLs from a text file (one URL per line).
/// Empty lines and `#` comments are skipped.
pub fn load_url_list(path: &str) -> Result<Vec<String>> {
    if !Path::new(path).exists() {
        anyhow::bail!("URL list file does not exist: {}", path);
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read URL list: {}", path))?;

    let urls: Vec<String> = content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_string())
        .collect();

    if urls.is_empty() {
        anyhow::bail!("URL list is empty (no usable lines): {}", path);
    }

    Ok(urls)
}

/// Resolve a single URL or a `--url-list` file into a target list.
pub fn resolve_targets(url: Option<&str>, url_list: Option<&str>) -> Result<Vec<String>> {
    match (url, url_list) {
        (Some(u), None) => {
            let u = u.trim();
            if u.is_empty() {
                anyhow::bail!("Target URL is empty");
            }
            Ok(vec![u.to_string()])
        }
        (None, Some(path)) => load_url_list(path),
        (Some(_), Some(_)) => {
            anyhow::bail!("Provide either a URL or --url-list, not both")
        }
        (None, None) => {
            anyhow::bail!("Provide a target URL or --url-list <file>")
        }
    }
}
