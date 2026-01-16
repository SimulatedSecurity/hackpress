use anyhow::{Context, Result};
use crate::models::VulnerabilityDatabase;
use crate::constants;
use std::fs;
use std::path::Path;

pub struct DatabaseManager;

impl DatabaseManager {
    pub fn load_vulns() -> Result<VulnerabilityDatabase> {
        // Load from local database/vulns.json file
        // Use 'hackpress update' to update databases from GitHub
        let vulns_path = format!("{}/vulns.json", constants::DATABASE_DIR);
        if Path::new(&vulns_path).exists() {
            let content = fs::read_to_string(&vulns_path)
                .context("Failed to read vulnerabilities database")?;
            let db: VulnerabilityDatabase = serde_json::from_str(&content)
                .context("Failed to parse vulnerabilities database")?;
            return Ok(db);
        }

        // If not found, return empty database instead of auto-updating
        // User must run 'hackpress update' explicitly
        Ok(VulnerabilityDatabase { vulnerabilities: vec![] })
    }

    pub fn download_vulns_db() -> Result<()> {
        // Download only vulns.json from GitHub
        let vulns_path = format!("{}/vulns.json", constants::DATABASE_DIR);
        let download_url = format!("{}/{}/{}/{}/{}/vulns.json",
            constants::GITHUB_RAW_BASE,
            constants::GITHUB_REPO_OWNER,
            constants::GITHUB_REPO_NAME,
            constants::GITHUB_BRANCH,
            constants::GITHUB_DATABASE_PATH);
        
        // Create database directory if it doesn't exist
        fs::create_dir_all(constants::DATABASE_DIR)
            .context("Failed to create database directory")?;

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(constants::DEFAULT_HTTP_TIMEOUT))
            .user_agent(format!("hackpress/{}", constants::VERSION))
            .build()
            .context("Failed to create HTTP client")?;
        
        let response = client
            .get(&download_url)
            .send()
            .context("Failed to download vulns.json from GitHub")?;
        
        if !response.status().is_success() {
            anyhow::bail!("Failed to download vulns.json (status: {})", response.status());
        }

        let content = response.text()
            .context("Failed to read vulns.json content")?;
        
        // Validate JSON before writing
        let _: VulnerabilityDatabase = serde_json::from_str(&content)
            .context("Invalid vulns.json format")?;
        
        fs::write(&vulns_path, content)
            .context("Failed to write vulns.json")?;

        Ok(())
    }

    pub fn update_all() -> Result<()> {
        println!("Downloading database folder from GitHub...");
        println!("Repository: {}/tree/{}/{}", 
            constants::REPOSITORY_URL,
            constants::GITHUB_BRANCH,
            constants::GITHUB_DATABASE_PATH);
        
        // Create database directory if it doesn't exist
        fs::create_dir_all(constants::DATABASE_DIR)
            .context("Failed to create database directory")?;

        // Fetch list of files from GitHub API
        let api_url = format!("{}/{}/{}/contents/{}",
            constants::GITHUB_API_BASE,
            constants::GITHUB_REPO_OWNER,
            constants::GITHUB_REPO_NAME,
            constants::GITHUB_DATABASE_PATH);
        
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(constants::DEFAULT_HTTP_TIMEOUT))
            .user_agent(format!("hackpress/{}", constants::VERSION)) // GitHub API requires User-Agent
            .build()
            .context("Failed to create HTTP client")?;
        
        let response = client
            .get(&api_url)
            .send()
            .context("Failed to fetch database folder contents from GitHub")?;
        
        if !response.status().is_success() {
            anyhow::bail!("Failed to fetch database folder from GitHub (status: {}). Please check your internet connection and ensure the repository is accessible.", response.status());
        }

        // Parse GitHub API response (array of file objects)
        let files: Vec<serde_json::Value> = response.json()
            .context("Failed to parse GitHub API response")?;
        
        let mut downloaded_count = 0;
        let mut failed_count = 0;

        // Download each file
        for file_obj in files {
            let file_type = file_obj.get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("");
            
            // Skip subdirectories, only download files
            if file_type != "file" {
                continue;
            }

            let filename = file_obj.get("name")
                .and_then(|n| n.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing 'name' field in GitHub API response"))?;
            
            let download_url = file_obj.get("download_url")
                .and_then(|u| u.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing 'download_url' field for file: {}", filename))?;

            // Download file
            println!("  Downloading {}...", filename);
            let file_response = client
                .get(download_url)
                .send()
                .context(format!("Failed to download {} from GitHub", filename))?;
            
            if !file_response.status().is_success() {
                eprintln!("    Warning: Failed to download {} (status: {})", filename, file_response.status());
                failed_count += 1;
                continue;
            }

            let content = file_response.text()
                .context(format!("Failed to read content of {}", filename))?;
            
            // Save file to local database directory
            let file_path = format!("{}/{}", constants::DATABASE_DIR, filename);
            fs::write(&file_path, content)
                .context(format!("Failed to write {}", filename))?;
            
            println!("    ✓ {} downloaded successfully", filename);
            downloaded_count += 1;
        }

        if downloaded_count > 0 {
            println!("✓ Successfully downloaded {} file(s) from database folder", downloaded_count);
        }
        
        if failed_count > 0 {
            eprintln!("⚠ Warning: Failed to download {} file(s)", failed_count);
        }

        if downloaded_count == 0 && failed_count == 0 {
            eprintln!("⚠ Warning: No files found in database folder on GitHub");
        }

        Ok(())
    }
}
